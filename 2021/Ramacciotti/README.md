# Progetto di Gestione di Rete

### Uso di SNMP per collezionare dati, analisi statica e tramite Double Exponential Smoothing

---

### Dipendenze

```sh
sudo apt install python3 snmp snmp-mibs-downloader libsnmp-dev
pip3 install easysnmp plotly
```

### Setup

Modificare il file il file `/etc/snmp/snmpd.conf` inserendo la riga `pass .1.3.6.1.2.1.25.1.0 /bin/sh /etc/snmp/cputemp.sh` e muovere il file `cputemp.sh` dalla repository in `/etc/snmp/`.

Creare un file `config.json` nella repository con la seguente struttura:
```json
{
	"host": "",
	"version": ,
	"community": "",
	"bot": "",
	"chat": ""
}
```
I primi tre valori da inserire corrispondono al monitoring SNMP (indirizzo ip dell'host da monitorare, versione di SNMP e community). Successivamente, il primo valore rappresenta il token di un bot di Telegram di cui abbiamo il controllo (utilizzare @BotFather per crearlo) e come secondo valore il proprio id di chat sul quale vogliamo ricevere i messaggi (per trovarlo è sufficiente iniziare una chat con il bot @getidsbot).

NB: se si desidera monitorare un computer diverso da localhost, è necessario che il primo passaggio di setup (con il file `snmpd.conf` e `cputemp.sh`) venga effettuato sulla macchina da monitorare.

### Run

Dopo aver eseguito le operazioni di setup, è possibile eseguire il codice con il comando `python3 main.py`.

### Programma

Il programma analizza uptime, carico e temperatura della cpu, ottetti in entrata e in uscita. Per la cpu, viene segnalato un errore se la temperatura supera i 75°C o se il carico supera l'80%. Per gli ottetti in entrata e in uscita invece, vengono calcolati con il double exponential smoothing i valori predetti ad ogni iterazione; quindi, con lo scarto quadratico medio, si trova l'errore medio di predizione, con il quale si identifica una banda di confidenza all'interno della quale non viene segnalato un errore. Se il valore misurato effettivamente si trova al di sotto del limite minimo o al di sopra del massimo, viene segnalato tramite un messaggio del bot di Telegram.
