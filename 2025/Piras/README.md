# ICS-Modbus-Analyzer

## 📌 Protocollo Modbus e Function Code

Modbus è un protocollo di comunicazione industriale master/slave, molto diffuso nei sistemi SCADA e ICS. I messaggi Modbus includono un **Function Code (FC)** che indica il tipo di operazione richiesta.

### 📌 Esempi comuni di Function Code:
- `01` - Read Coils
- `02` - Read Discrete Inputs
- `03` - Read Holding Registers (tipico per HMI)
- `04` - Read Input Registers (tipico per HMI)
- `05` - Write Single Coil
- `06` - Write Single Register (tipico per PLC)
- `15` - Write Multiple Coils
- `16` - Write Multiple Registers (tipico per PLC)
- `43` - Encapsulated Interface (spesso usato per diagnostica, anche potenzialmente malevola)

Il sistema di analisi utilizza queste informazioni per:
- Identificare comportamenti sospetti (es. FC non attesi → anomalie)
- Classificare i dispositivi in base alle FC usate (es. HMI vs PLC)
- Generare profili di comunicazione per ogni IP

### Documentazione: 
``` https://modbus.org/specs.php ```

## 📌 Descrizione del progetto

ICS-Modbus-Analyzer è uno strumento per l'analisi passiva di traffico Modbus/TCP in ambienti ICS. Permette di estrarre, classificare e analizzare pacchetti da file `.pcap`, evidenziando comportamenti anomali e profilando automaticamente i dispositivi presenti nella rete.

Questa versione include:
- Parsing di file `.pcap`
- Estrazione automatica di IP, Function Code e timestamp
- Ordinamento temporale globale e generazione di `parsed_data.csv`
- Analisi delle anomalie (function code inattesi o blacklistati)
- Classificazione automatica dei dispositivi in PLC / HMI / unknown
- Generazione di profili comportamentali per ogni IP
- Visualizzazione temporale del traffico

### Logica di classificazione

🟦 PLC – Dispositivi che ricevono comandi di scrittura (Function Code 5, 6, 15, 16)  
🟨 HMI/SCADA – Dispositivi che inviano richieste di lettura (Function Code 3, 4)  
⚪ Unknown – Dispositivi coinvolti nel traffico ma che non soddisfano nessuno dei criteri sopra  

Per garantire una classificazione corretta, lo script analizza solo il primo pacchetto per ogni tcp.stream, assumendo che contenga la vera richiesta Modbus:

```python
if stream in seen_streams:
    continue
seen_streams.add(stream)
```
### Esempio di classificazione

| Time                  | SrcIP             | DstIP         | FunctionCode | TCPStream |
| --------------------- | ----------------- | ------------- | ------------ | --------- |
| 2025-07-10 14:01:32.1 | **192.168.1.100** | 192.168.1.10  | **3**        | 0         |
| 2025-07-10 14:01:32.2 | 192.168.1.10      | 192.168.1.100 | 3            | 0         |
| 2025-07-10 14:01:35.4 | **192.168.1.100** | 192.168.1.20  | **4**        | 1         |
| 2025-07-10 14:01:35.5 | 192.168.1.20      | 192.168.1.100 | 4            | 1         |
| 2025-07-10 14:01:38.0 | **192.168.1.101** | 192.168.1.30  | **16**       | 2         |
| 2025-07-10 14:01:38.2 | 192.168.1.30      | 192.168.1.101 | 16           | 2         |

192.168.1.100 ha inviato richieste con Function Code 3 e 4 → classificato come HMI/SCADA  
192.168.1.30 ha ricevuto una richiesta con Function Code 16 → classificato come PLC  
192.168.1.101 ha inviato un comando di scrittura → non classificato come HMI (solo letture), quindi → Unknown  

### Semplificazione

Nella realtà un PLC risponde ad un qualsiasi comando con una sorta di ack il quale consiste nello stesso identico pacchetto rispedito al mittente.
Quindi nella pratica si dovrebbe considerare una sorta di delay tra i vari pacchetti e anche l'inversione di destinazione e sorgente, per distinguere comandi da ack.
Da qui anche il fatto che viene analizzato solo il primo pacchetto di uno stream, senza considerare che lo stesso stream potrebbe essere usato per diversi comandi.

Nella logica semplificata che abbiamo adottato, vogliamo evitare ambiguità con i PLC, che:
Ricevono FC 5/6/15/16 → quindi se un IP riceve scritture, è quasi certamente un PLC
Ma se un IP invia FC 5/6/15/16, può essere un HMI, oppure un altro controllore, oppure un attaccante.

Quindi, per minimizzare falsi positivi, ci limitiamo a definire tale classificazione:

Un HMI è un dispositivo che invia FC di lettura (3, 4)
Un PLC è un dispositivo che riceve FC di scrittura (5, 6, 15, 16)

### Anomalie

Se viene rilevato un pacchetto contenente function code non presenti tra quelli previsti dal file di configurazione,
o viene rilevato un pacchetto il cui function code si trova nella blacklist fornita attraverso lo stesso, viene segnalata una anomalia.

Anomalie sono segnalate anche dal modulo di verifica dei profili 'profile_check.py' nel caso in cui vengano rilevati, dal
csv della più recente scansione, operazioni con function code rimasti sino ad allora inutilizzati dagli stessi device sotto osservazione.

---

### 🔎 Dettagli tecnici

- Tutti i **parametri di esecuzione** sono definiti nel file `config.cfg`, che viene letto automaticamente.
  - `input_pcap`: file di input `.pcap` contenente traffico Modbus
  - `parsed_csv`: file CSV che conterrà i pacchetti estratti e processati
  - `output_json`: (se usato nel modulo di analisi) contiene anomalie rilevate
  - `chunk_size`: numero di pacchetti per file chunk
  - `blacklist`: lista di codici Modbus considerati pericolosi
  - `expected`: lista di codici Modbus attesi nel sistema

Le anomalie vengono segnalate nel file `anomalies.json` con motivo e metadati.

---

### 🔎 Descrizione dei moduli

- Il modulo di **parser**:
  - Estrae pacchetti Modbus dal file `.pcap`
  - Salva un file `parsed_data.csv` con i campi: `Time`, `SrcIP`, `DstIP`, `FunctionCode`, `TCPstream`

- Il modulo **analyze** (opzionale, vedi `analyze()`):
  - Legge `parsed_data.csv`
  - Verifica se i FunctionCode appartengono alla lista `expected`
  - Verifica se i FunctionCode appartengono alla lista `blacklist`
  - Se un codice non è atteso, viene salvata un’anomalia nel file `anomalies.json`

- Il modulo **classify_roles**:
  - Legge `parsed_data.csv`
  - Assegna a ciascun IP un ruolo (`PLC`, `HMI`, `unknown`) in base ai codici funzione usati
  - Può stampare o salvare i risultati per ulteriori analisi

- Il modulo **build_profiles**:
  - Legge `parsed_data.csv`
  - Costruisce profili per ogni IP basati sulla frequenza e tipo di codici Modbus usati
  - Salva il risultato in `profiles.json`

- Il modulo **profile_check (standalone)**:
  - Legge `parsed_data.csv`
  - Verifica che il comportamento della nuova cattura sia coerente col profilo costruito nella precedente
  - Segnala eventuali anomalie
  - è necessario che sia gia stata eseguita due volte l'analisi di catture di pacchetti: andrò infatti a confrontare il profilo dei device, scritto a partire da una cattura precedente, con quello di una nuova scansione.

---

### ⚙️ Requisiti

- Python 3.x
- `pyshark`

### Installazione:

```bash
pip install pyshark
sudo apt install tshark
```

---

### ▶️ Come usare il progetto

1. Posiziona un file `.pcap` chiamato `modbus_sample.pcap` nella directory del progetto

2. Avvia il tool:
```bash
python3 ics_modbus_analyzer.py
```

3. Check anomalie profili:
```bash
python3 profile_check.py
```
---

### ✅ Esempio output `parsed_data.csv`
```csv
Time,SrcIP,DstIP,FunctionCode,TCPstream
2024-06-01 12:45:03,192.168.1.2,192.168.1.10,3,0
2024-06-01 12:45:04,192.168.1.2,192.168.1.10,6,1
2024-06-01 12:45:05,192.168.1.3,192.168.1.10,43,2
```

### ✅ Esempio `anomalies.json`
```json
[
  {
    "time": "2024-06-01 12:45:05",
    "src": "192.168.1.3",
    "dst": "192.168.1.10",
    "func": "43",
    "reason": "Blacklisted function code"
  }
]
```

### ✅ Esempio `config.cfg`
```text
input_pcap=modbus_sample.pcap
parsed_csv=parsed_data.csv
anomalies_json=anomalies_json
profiles=profiles_json
blacklist=43,8,22
expected=3,4,6,15,16
```

---
