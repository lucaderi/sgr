## InOutOctetsCheck

INSTALLATION:
- You need to install these packages before running the script:
    - pip3 install easysnmp
    - pip3 install influxdb-client
- You also need to have influxdb installed and running on your pc before running the script. After the execution of influxdb locally, visit the url http://localhost:9999, take the token of your influxdb and add it to the script replacing mine currently on the script.

DESCRIPTION:
- It is a simple python script that, using influxdb, records the values of ifInOctets and ifOutOctets obtained with snmp. To see the graph, visit http://localhost:9999 and select the correct filters and bucket of your influxdb.

USAGE: 
- ./InOutCheck.py
