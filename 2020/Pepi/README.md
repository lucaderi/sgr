# snmp-Cpu-Memory-GUI
A small app that shows some information of a host using snmp

## Installation
You need to have Easy SNMP library and tkinter installed on your system:
```
sudo apt-get install libsnmp-dev snmp-mibs-downloader
sudo apt-get install gcc python3-dev
pip3 install easysnmp
sudo apt-get install python3-tk
```
Sometimes it is necessary to edit the snmp configuration file: snmpd.config, located in /etc/snmp/.   
You must add the following lines to the file:
```
view   systemonly  included   .1.3.6.1.4.1.8072
view   systemonly  included   .1.3.6.1.4.1.2021

```
## Usage
For info on your machine: `./snmpCPUMemory.py`  
For info on other machine: `./snmpCPUMemory.py <community> <hostname>`
