# Introduction
Monitors, through SNMP commands, the following:

- RAM usage 
- Disk usage 
- CPU usage 

Then through the use of double exponential smoothing predicts the expected value at time t+1, also calculates a Higher Band/Lower Band for values read.
If these values happen to be outside of these bounds an alert shall be sent through telegram.\
The alerts also trigger if the percentage usage of RAM/disk/CPU exceeds 90%.
All relevant data (usage, %usage, bands, predictions) will be saved to InfluxDB where the user may check the data in the form of graphs or tables.\
InfluxDB tasks are used to handle the alert functionalities of the application. \
The application has been developed and tested in ubuntu using python 3.8.

# Requirements
-InfluxDB 2.X \
-Python 3.8 \
-easysnmp 

You can get InfluxDB from its official site here: https://www.influxdata.com/get-influxdb/ \

For easysnmp you need to open the terminal and type the following command:
```sh
sudo apt install snmp snmpd snmp-mibs-downloader libsnmp-dev
```
then edit the snmp.conf file (by default found in: /etc/snmp/) so that loading MIBs is allowed.

You also need to install the following packages for python:
```sh
pip install influxdb-client
pip install easysnmp
```

A properly configured telegram bot to send the alerts to is also necessary.

# Setup

- Open "configFile.py" inside the System Monitor folder and insert your InfluxDB token, org and bucket
- Make sure the Influxd service is running, open your browser and navigate to localhost:8086, then click on tasks in the sidebar and create a new task
- Copy the script found in "cpuInfluxTask.flux" into your new task and make sure to set proper values for the "bucketName", "tokenTel" and "channelTel" variables
- Repeat the two previous steps for the "diskInfluxTask.flux" and the "ramInfluxTask.flux" files

# Usage

Execute "SystemMonitorMain.py":
```sh
python3.8 SystemMonitorMain.py
```
The application is now monitoring, open your browser and navigate to localhost:8086 to check on the data that is being saved to the DB.
Whenever you're done press CTRL+c to stop the application.
