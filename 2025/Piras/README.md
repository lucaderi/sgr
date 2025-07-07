# ICS-Modbus-Analyzer

### 📌 Descrizione del progetto

ICS-Modbus-Analyzer è uno strumento per l'analisi passiva di traffico Modbus/TCP in ambienti ICS. Permette di estrarre, classificare e analizzare pacchetti da file `.pcap`, evidenziando comportamenti anomali e profilando automaticamente i dispositivi presenti nella rete.

Questa versione include:
- Parsing parallelo di file `.pcap` tramite splitting e multiprocessing
- Estrazione automatica di IP, Function Code e timestamp
- Ordinamento temporale globale e generazione di `parsed_data.csv`
- Analisi delle anomalie (function code inattesi o blacklistati)
- Classificazione automatica dei dispositivi in PLC / HMI / unknown
- Generazione di profili comportamentali per ogni IP
- Visualizzazione temporale del traffico

---

## ℹ️ Protocollo Modbus e Function Code

Modbus è un protocollo di comunicazione industriale master/slave, molto diffuso nei sistemi SCADA e ICS. I messaggi Modbus includono un **Function Code (FC)** che indica il tipo di operazione richiesta.

### 🔢 Esempi comuni di Function Code:
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

---

### ⚙️ Requisiti

- Python 3.x
- `pyshark`
- `editcap` (parte di Wireshark)

#### Installazione:
```bash
pip install pyshark
sudo apt install wireshark  # o brew install wireshark su macOS
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

### 🔎 Dettagli tecnici

- Tutti i **parametri di esecuzione** sono definiti nel file `config.cfg`, che viene letto automaticamente.
  - `input_pcap`: file di input `.pcap` contenente traffico Modbus
  - `parsed_csv`: file CSV che conterrà i pacchetti estratti e processati
  - `output_json`: (se usato nel modulo di analisi) contiene anomalie rilevate
  - `threads`: numero di thread da usare nel parser
  - `chunk_size`: numero di pacchetti per file chunk
  - `blacklist`: lista di codici Modbus considerati pericolosi
  - `expected`: lista di codici Modbus attesi nel sistema

Le anomalie vengono segnalate nel file `anomalies.json` con motivo e metadati.

La classificazione dei dispositivi segue questa logica:
- Se un IP usa FC di scrittura (`6`, `5`, `15`, `16`) + lettura: → `PLC`
- Se usa solo FC `3` o `4`: → `HMI`
- Altrimenti: → `unknown`

---

### 🔎 Descrizione dei moduli

- Il modulo di **parser**:
  - Estrae pacchetti Modbus dal file `.pcap`
  - Salva un file `parsed_data.csv` con i campi: `Time`, `SrcIP`, `DstIP`, `FunctionCode`

- Il modulo **analyze** (opzionale, vedi `analyze()`):
  - Legge `parsed_data.csv`
  - Verifica se i FunctionCode appartengono alla lista `expected`
  - Se un codice non è atteso, viene salvata un’anomalia nel file `anomalies.json`

- Il modulo **classify_roles**:
  - Legge `parsed_data.csv`
  - Assegna a ciascun IP un ruolo (`PLC`, `HMI`, `unknown`) in base ai codici funzione usati
  - Le classificazioni si basano su regole semplici, es. `3/4` → HMI, `6/16` → PLC
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

### ✅ Esempio output `parsed_data.csv`
```csv
Time,SrcIP,DstIP,FunctionCode
2024-06-01 12:45:03,192.168.1.2,192.168.1.10,3
2024-06-01 12:45:04,192.168.1.2,192.168.1.10,6
2024-06-01 12:45:05,192.168.1.3,192.168.1.10,43
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
threads=16
blacklist=43,8,22
expected=3,4,6,15,16
```

---
