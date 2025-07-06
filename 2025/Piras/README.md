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

### 📂 Struttura dei file principali

| File                | Descrizione |
|---------------------|-------------|
| `parser_parallel.py`| Parsing del pcap in parallelo + generazione CSV |
| `analyzer.py`       | Analisi di anomalie nei function code |
| `classify.py`       | Classificazione dei dispositivi in base ai function code usati |
| `profile_builder.py`| Generazione dei profili IP (function code e volume) |
| `visualize.py`      | Rappresentazione testuale del traffico nel tempo |
| `parsed_data.csv`   | CSV generato dal parser contenente i dati base |
| `anomalies.json`    | Output JSON delle anomalie rilevate |
| `profiles.json`     | Output JSON dei profili comportamentali IP |

---

### ⚙️ Requisiti

- Python 3.x
- `pyshark`
- `editcap` (parte di Wireshark)

#### Installazione:
```bash
pip install pyshark
sudo apt install wireshark  # o brew install wireshark su macOS
```

---

### ▶️ Come usare il progetto

1. Posiziona un file `.pcap` chiamato `modbus_sample.pcap` nella directory del progetto

2. Avvia il parsing parallelo:
```bash
python parser.py
```

3. Analizza le anomalie:
```bash
python analyzer.py
```

4. Classifica i dispositivi:
```bash
python classify.py
```

5. Genera i profili IP:
```bash
python profile_builder.py
```

6. Visualizza la timeline di traffico:
```bash
python visualize.py
```

---

### 🔎 Dettagli tecnici

- **Function code attesi**: `1 2 3 4 5 6 15 16`
- **Function code blacklistati**: `8 20 21 43`

Le anomalie vengono segnalate nel file `anomalies.json` con motivo e metadati.

La classificazione dei dispositivi segue questa logica:
- Se un IP usa FC di scrittura (`6`, `5`, `15`, `16`) + lettura: → `PLC`
- Se usa solo FC `3` o `4`: → `HMI`
- Altrimenti: → `unknown`

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

---
