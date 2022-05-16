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
- InfluxDB 2.X 
- Python 3.8 
- easysnmp 

You can get InfluxDB from its official site here: https://www.influxdata.com/get-influxdb/ 
For easysnmp you need to open the terminal and type the following command:
```sh
sudo apt install snmp snmpd snmp-mibs-downloader libsnmp-dev
```
then edit the snmp.conf file (by default found in: /etc/snmp/) and do the following: 
- Comment out the line that says "mibs :" (add '#' at the start of the line) 
- Remove the '#' in the line that starts with "mibdirs..." 

The file should look like this:  \
![image](https://user-images.githubusercontent.com/84874362/168674689-7bb5d1a0-17d4-4161-a71f-d339b20e0fca.png) \
Also make sure that your snmpd.conf file allows the use of the OID's present in the software (1.3.6.1.2.1.25.2.3.1.* , 1.3.6.1.2.1.25.3.3.1.* and 1.3.6.1.4.1.2021.4.* ) \
For example, this is a bare-bones snmpd.conf file that lets you run the program: \
![image](https://user-images.githubusercontent.com/84874362/168678693-e3e8f650-4318-47bf-800c-609779983f6b.png)


You also need to install the following packages for python:
```sh
pip install influxdb-client
pip install easysnmp
```

A properly configured telegram bot to send the alerts to is also necessary.

# Setup

- Open "configFile.py" inside the System Monitor folder and insert your InfluxDB token, org and bucket
- Make sure the Influxd service is running, open your browser and navigate to localhost:8086, then click on tasks in the sidebar and create a new task
- Give the task a name and a frequency then copy the script found in "cpuInfluxTask.flux" into it and make sure to set proper values for the "bucketName", "tokenTel" and "channelTel" variables
- Repeat the two previous steps for the "diskInfluxTask.flux" and the "ramInfluxTask.flux" files

# Usage

Execute "SystemMonitorMain.py":
```sh
python3.8 SystemMonitorMain.py
```
The application is now monitoring, open your browser and navigate to localhost:8086 to check on the data that is being saved to the DB.
Whenever you're done press CTRL+c to stop the application.
