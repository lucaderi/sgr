

## Description
This tool is composed by two scripts and monitors traffic network and bandwidth usage on a network interface.

The first script, traffic_network.py, is like a daemon: first it shows all network interfaces on the host and asks the user to choose one of them. After that, monitoring on the chosen interface starts. The script builds the rrd database and two RRA. The first archive maintains raw data for an hour, while the second one maintains the average per minute for a week. 

The second script, build_graphs.py, creates two graphs, one for traffic network and one for bandwidth usage. This script asks in input the rrd file on which make graphs and the time interval.

Scripts must be in the same directory, as well as databases and graphs.

## Configuration
Data about the chosen network interface are under the "interface group", in IF-MIB. 
So, to avoid problems like "no such object", add the following line to snmpd.conf file:
```bash
view systemonly included .1.3.6.1.2.1.2
```

## Installation
To install [EasySNMP](https://easysnmp.readthedocs.io/en/latest/) library on Debian/Ubuntu systems:
```bash
sudo apt-get install libsnmp-dev snmp-mibs-downloader
sudo apt-get install gcc python-dev
pip3 install easysnmp
```
To build bindings for [RRDtool](https://pythonhosted.org/rrdtool/) for Python3 on Debian/Ubuntu systems:
```bash
sudo apt-get install librrd-dev libpython3-dev
pip3 install rrdtool
```

## Usage
First,  make sure that agent SNMP is running and all MIBS are loaded. Otherwise, the user can type the following command on the shell:
```python
export MIBS=all
```
Then, the user have to start the script that creates the database and monitors the chosen network interface.
```python
python3 traffic_network.py
```
Later, the user can see graphs, running the following script on another shell. Graphs' time interval is required in input.
```python
python3 build_graphs.py
```

## Output
Monitoring during a Microsoft Teams session

![example](traffic_network\example.png)
