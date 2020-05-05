## InOutOctetsCheck

INSTALLATION:
- You need to install these packages before running the script:
    - pip3 install easysnmp
    - pip3 install influxdb-client
- You need also to have installed influxdb on your pc and run it before running the sript. After the execution of influxdb in local you have to visit the url http://localhost:9999 and take the token of your influxdb for change it instead of mine on the script.

DESCRIPTION:
- It's a simple python script that using influxdb, records the values of ifInOctets and ifOutOctets obtained with snmp. To see the graph you have to visit http://localhost:9999 and select the correct filters and bucket of your influxdb.

USAGE: 
- ./InOutCheck.py
