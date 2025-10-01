# Rilevatore SYN Scan (lucaderi#363) - Istruzioni

## Scopo

Questo programma monitora i pacchetti SYN in entrata su una macchina (assumendo di ricevere solo pacchetti SYN destinati alla macchina stessa) per rilevare potenziali port scan.

Quando viene individuato un IP sospetto:
- Viene stampato un avviso sul terminale
- Viene scritto su file di log  

Ogni minuto i dati vengono salvati in un database RRD e viene generato un grafico con i SYN degli ultimi 10 minuti.

---

## Requisiti

Assicurarsi che il sistema abbia installato:

```bash
sudo apt install build-essential libpcap-dev rrdtool xdg-utils nmap
```

- 'build-essential' per il compilatore e il comando 'make'
- 'libpcap-dev' per catturare pacchetti
- 'rrdtool' per database e grafici
- 'xdg-utils' per aprire il PNG
- 'nmap' per testare

---

## Compilazione

Eseguire nella cartella del progetto:

```bash
make
```

Questo creerà gli eseguibili:
- 'RilevatoreSynScan'
- 'Scan'

---

## Avvio del rilevatore

1. Avviare il rilevatore:

```bash
sudo ./RilevatoreSynScan
```

> **Modalità debug** (opzionale, stampa la tabella hash con IP sospetti e SYN in tempo reale):

```bash
sudo ./RilevatoreSynScan -d
```

2. Scegliere l’interfaccia da monitorare (verranno elencate e numerate).
> **Nota**: l’interfaccia 'any' non è supportata, perché non fornisce un header Ethernet standard.

3. Il programma si arresta con Ctrl+C.

---

## Test di una scansione (su un’altra shell)

Per simulare uno scan locale (solo sulla tua macchina o host autorizzati):

```bash
sudo ./Scan
```

- Il programma chiederà se si vuole scansionare 'localhost' o un altro IP.

Oppure usare direttamente 'nmap':

```bash
sudo nmap -sS -p 1-1024 <target-ip>
```

---

## Cosa succede quando viene rilevato uno scan

- Sul terminale comparirà un messaggio di allarme con l’IP sospetto.
- L’evento viene scritto in 'scan_alert.log'.
- I SYN raccolti nell’ultimo minuto vengono aggiornati in 'scan.rrd' e viene rigenerato 'scan.png'.

## Visualizzazione grafici

- Per visualizzare i grafici:

```bash
xdg-open scan.png
```

## Generazione grafici orari e giornalieri

- Il file '.rrd' tiene traccia anche dei dati dell'ultima ora e dell'ultimo giorno.
- Lo script 'GeneraGrafici.sh' genera 'scan-1h.png' e 'scan-1g.png'.
- Per eseguire lo script la prima volta:

```bash
chmod +x GeneraGrafici.sh
./GeneraGrafici.sh
```

- Da quel momento in poi, per rigenerare i grafici:

```bash
./GeneraGrafici.sh
```
