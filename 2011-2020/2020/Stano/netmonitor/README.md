
## Overview
This script monitors target host interface inbound and outbound traffic using SNMP, and can olso crete graphs of the network traffic using rrd_graph.
Data is stored in a rrd database in a 24h period whit a step of 1 minute.

## System Requirements
This script needs an snmp daemon running on the target host. To install snmp:

```bash
sudo apt-get update
sudo apt-get install snmp snmpd snmp-mibs-downloader
sudo download-mibs
```

```bash
sudo nano /etc/snmp/snmp.conf
```
Add the following line to /etc/snmp/snmp.conf:
```
mibs +ALL

```

This scripts retrieves net traffic data using the "interface group":
```bash
sudo nano /etc/snmp/snmpd.conf
```
Add the following line to /etc/snmp/snmpd.conf file:
```
view systemonly included .1.3.6.1.2.1.2
```

Restart snmpd service:
```
sudo service snmpd restart
```

## Script Installation
To install [EasySNMP](https://easysnmp.readthedocs.io/en/latest/), [RRDtool](https://pythonhosted.org/rrdtool/) and [Argh](https://github.com/neithere/argh/) libraries:
```bash
sudo apt-get install gcc python-dev libsnmp-dev snmp-mibs-downloader librrd-dev libpython3-dev
pip3 install easysnmp rrdtool argh
```

## Usage
This scripts has two sub-commands {netmonitor,graph}. For help:
```
python3 netmonitor.py -h
python3 netmonitor.py netmonitor -h
python3 netmonitor.py graph -h
```

To start monitoring on localhost:
```
python3 netmonitor.py netmonitor
```
this will create an *.rrd file (Ex: a.rrd). To create a graph:
```
python3 netmonitor.py graph a.rrd
```
