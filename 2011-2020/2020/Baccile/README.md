# snmp_stat

snmp_stat è uno script che fa delle richieste di GET ad un daemon SNMP in esecuzione sulla macchina corrente. Le richieste che vengono effetuate servono a ricavare informazioni statistiche sulla CPU e sulla RAM dell'host interrogato. Il daemon viene interrogato ciclicamente ogni secondo per un numero di volte scelto.

## Installation

E' necessario installare i seguenti pacchetti su Ubuntu per garantire il funzionamento di snmp_stat.

```bash
sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
```

Inoltre tramite il package manager pip è necessario installare [EasySNMP](https://easysnmp.readthedocs.io/en/latest/).
```bash
pip3 install easysnmp
```

## Usage

Per l'esecuzione basta eseguire il seguente comando.

```bash
python3 snmp_stat.py
```

In questo modo snmp_stat fa delle richieste di default al daemon sul localhost, alla community public e con la versione 1 di SNMP. Le richieste saranno fatte per 5 volte a distanza di un secondo l'una dall'altra.

E' possibile personalizzare l'esecuzione con il seguente comando.

```bash
python3 snmp_stat.py [hostname community version] [numero di richieste]
```
