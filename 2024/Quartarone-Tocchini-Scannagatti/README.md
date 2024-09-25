# Analisi Statistica su Rete Ospedaliera con nDPI
## Corso: Gestione di Rete 2023/2024
### Autori: Angelo Quartarone, Tommaso Tocchini, Gabriele Scannagatti

## Descrizione del Progetto
Questo progetto utilizza strumenti statistici per analizzare la rete di un'infrastruttura ospedaliera, con un'attenzione particolare alla rilevazione di attacchi DoS/DDoS.

## Caratteristiche
- Analisi del traffico di rete: Monitoraggio del traffico con statistiche dettagliate su byte e pacchetti scambiati, durata dei flussi e distribuzione del traffico per protocollo.
- Rilevazione anomalie: Identificazione degli outlier basata su metriche come il goodput, la lunghezza dei pacchetti e l'utilizzo dei flag TCP.

## Prerequisiti
- python
- ndpiReader
- wireshark

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

### Riproduzione Test
- Scaricare i file pcap da: https://drive.google.com/drive/folders/1LDs8K32zsLVVAleuv_e5ZK1crTJC6gaZ?usp=sharing
- Eseguire il programma ndpiReader con le seguenti opzioni:
```bash
./ndpiReader -i {file pcap da analizzare} -C {nome file csv da generare}
```
- Eseguire MQTTAnalizer con il file csv prodotto nel passo precedente:
```bash
python3 src/mqttanalizer.py -f {path file csv da analizzare} -F ack rst -O {path directory in cui salvare i grafici generati}
```
#### Verifica Risultati
Essendo i dataset non etichettati in modo specifico sull'identità degli attaccanti, per verificare i risultati, è necessaria un'analisi manuale tramite wireshark:
- per alcuni file di test, la rilevazione delle anomalie può avvenire attraverso la sezione "expert information dialog".
- per tutti i file di test, la rilevazione delle anomalie è identificabile attraverso la sezione "conversation", selezionando la schermata "IPv4" e ordinando i bytes in ordine decrescente.
- per tutti i file di test, la rilevazione è possibile verificando che gli ip generati dal programma siano associati ai dispositivi "Raspberry Pi" (selezionando un pacchetto, è possibile visualizzare questa informazione sul campo ethernet), che, come spiegato all'interno della relazione, sono stati utilizzati come attaccanti. 

### Output
Il programma restituisce in output un report sul terminale contenente:
- Statistiche generali della cattura.
- Analisi statistica della cattura con eventuale rilevazione di anomalie.
- Grafici sintetici di quanto citato sopra.
