# **snmpstat.py**

## Description
A simple Python script that send GET requests to an host where a SNMP daemon is running.   
This script shows on the screen CPU load and memory usage about the remote host, whose name is required in input.

## Installation

To install Easy SNMP library on Debian/Ubuntu systems:

```bash
sudo apt-get install libsnmp-dev snmp-mibs-downloader
sudo apt-get install gcc python-dev
pip3 install easysnmp
```

## Usage

```python
python3 snmpstat.py
```

## Output
```bash
************ REPORT ************
[CPU LOAD]
1 minute load: ....
5 minute load: ....
10 minute load: ....

[MEMORY STATISTICS]
Total: .... kB
Available: .... kB
Buffered: .... kB
Cached: .... kb
************ END OF REPORT ************
```


