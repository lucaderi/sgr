# SNMP System Monitor (PCMonitor.py)

N.B. Questa versione non è compatibile con architetture ARMhf (Raspberry) in quanto queste non supportano la versione 2.x.x di InfluxDB.

Permette di monitorare in tempo reale i seguenti parametri tramite interrogazione SNMP:
  - Memoria RAM inutilizzata
  - Percentuale del disco occupata
  - Carico in percentuale della CPU (media ultimo minuto)

Tramite la web UI di Influx Data è possibile monitorare graficamente i parametri e impostare delle soglie di allarme.

## Dipendenze Python:
 - easysnmp
 - influxdb-client

## Requisiti per l'esecuzione:
  - InfluxDB 2 (amd64)
  - Servizio influxd avviato
  - Python 3.x

Per eseguire il programma:
```bash
python3 PCmonitor.py.sh
```  
Per arrestare il programma:
```bash
ctrl + c
```  

Per maggiori dettagli sulla configurazione consultare la relazione allegata.

# SNMP System Monitor (sysMonitor_ARM.py)

Questa versione, per motivi di compatibilità su Raspberry Pi 3, è basata sulla versione 1 di InfluxDB che non incorpora la web UI per poter monitorare le risorse in tempo reale ma necessita dei plugin Chronograf e Kapacitor.

Permette di monitorare in tempo reale i seguenti parametri tramite interrogazione SNMP:
  - Memoria RAM inutilizzata
  - Percentuale del disco occupata
  - Carico in percentuale medio della CPU (media ultimo minuto)

A differenza della versione amd64, in questa versione abbiamo un database influx locale che viene scritto mediante lo script Python, questo è associato al servizio Kapacitor che permette alla web UI Chronograph di monitorare costantemente i dati tramite browser alla porta 8888.

## Dipendenze Python:
 - easysnmp
 - influxdb-client
 - matplotlib

## Requisiti per l'esecuzione:
  - InfluxDB 1.x.x (armhf)
  - Chronograf
  - Kapacitor
  - Python 3.x

Per eseguire il programma:
```bash
python3 sysMonitor_ARM.py.sh
```  
Per arrestare il programma:
```bash
ctrl + c
```  
Per maggiori dettagli sulla configurazione e sull'utilizzo consultare la relazione allegata.
