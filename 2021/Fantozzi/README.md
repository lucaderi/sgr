# Info

Questo semplice script realizzato in Python è stato creato per monitorare il numero di processi attivi, la Ram occupata e la Ram libera di un sistema su cui gira un Agent SNMP.

# Installazione
Per poter utilizzare il software è necessario installare i seguenti pacchetti:
Python 3.9
easysnmp
rrdtool
con i seguenti comandi:

```bash
sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
pip3 install easysnmp
pip3 install rrdtool
```

Inoltre è necessario abilitare i MIB appropriati andando a modificare il file in "/etc/snmp/snmp.conf" basterà aprire il file con un editor di testo e modificare la riga "mibs: " commentandola così:

```bash
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs : 
```

# Utilizzo
Basterà digitare il comando:
```bash
python3 snmp_monitor_RamProcesses.py [hostname] [community]
```
Dove hostname è l'host target del monitoraggio e community è la community SNMP a quel punto compariranno alcune statistiche sul temrinale, mentre per monitorare il numero dei processi attivi basterà andare nella cartella reports (generata dal programma) e aprire i files .png corrispondenti alle metriche:

![alt text](https://github.com/irfanto05/Fantozzi/blob/main/ram_graph.png)
![alt text](https://github.com/irfanto05/Fantozzi/blob/main/process_graph.png)
![alt text](https://github.com/irfanto05/Fantozzi/blob/main/freeRam_graph.png)
