# Analisi Statistica su Rete Ospedaliera con nDPI
## Corso: Gestione di Rete 2023/2024
### Autori: Angelo Quartarone, Tommaso Tocchini, Gabriele Scannagatti

## Descrizione del Progetto
Questo progetto utilizza strumenti statistici per analizzare la rete di un'infrastruttura ospedaliera, con un'attenzione particolare alla rilevazione di attacchi DoS/DDoS.

## Caratteristiche
- Analisi del traffico di rete: Monitoraggio del traffico con statistiche dettagliate su byte e pacchetti scambiati, durata dei flussi e distribuzione del traffico per protocollo.
- Rilevazione anomalie: Identificazione degli outlier basata su metriche come il goodput, la lunghezza dei pacchetti e l'utilizzo dei flag TCP.

## Installazione
### Download Repository
```bash
git clone https://github.com/SpanishInquisition49/gestione_di_reti.git
```

### Creazione e Avvio Virtual Enviroment Python
```bash
python3 -m venv env
source env/bin/activate
```

### Installazione Librerie
```bash
pip3 install -r requirements.txt
```

### Avvio Programma
```bash
python3 mqttanalyzer.py [-h] -f FILE [-o OUTPUT] [-F FLAGS [FLAGS ...]]

An anomaly detection system for IoT networks

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The file to analyze
  -o OUTPUT, --output OUTPUT
                        The output directory for the graphs
  -F FLAGS [rst, ack, syn, psh, urg], --flags FLAGS [rst, ack, syn, psh, urg]
                        Flags to use for the analysis
```

### Output
Il programma restituisce in output un report sul terminale contenente:
- Statistiche generali della cattura.
- Analisi statistica della cattura con eventuale rilevazione di anomalie.
- Grafici sintetici di quanto citato sopra.