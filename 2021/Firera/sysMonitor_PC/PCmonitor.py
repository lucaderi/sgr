# SYSTEM RESOURCES MONITOR (CPU LOAD, FREE RAM, DISK USAGE)

# Launch this script for desired time and terminate the monitoring with ctrl+c
# Point your browser on localhost:8086 and follow the instructions
# In Boards section view realtime graphs

# IMPORTANT: this program requires InfluxDB installed on machine and influxd service started (sudo influxd).

from influxdb_client import Point, WritePrecision, InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import datetime
import time
import webbrowser as web
from easysnmp import Session
from conf import*


# snmp constants
HOSTNAME = 'localhost'
COMMUNITY = 'public'
OID_RAM_UNUSED = 'iso.3.6.1.4.1.2021.4.11.0'
OID_DISK_USAGE = 'iso.3.6.1.4.1.2021.9.1.9.1'
OID_CPU_USAGE = 'iso.3.6.1.2.1.25.3.3.1.2.196608'

# influxdb settings
client = InfluxDBClient(url="http://localhost:8086", token=INFLUXDB_TOKEN, org=INFLUXDB_ORGANIZATION)
write_api = client.write_api(write_options = SYNCHRONOUS)
delete_api = client.delete_api()
web.open_new_tab(f'http://{HOSTNAME}:8086')

# Initializing snmp session
session = Session(hostname=HOSTNAME, community=COMMUNITY, version=1)


print('Running...')
print('Press ctrl+c to stop monitoring ')

while True:
    try:
        point = Point("sys").tag("device", "laptop").field("availableram", int(session.get(OID_RAM_UNUSED).value)).field("cpuUsage", int(session.get(OID_CPU_USAGE).value)).field("disk_usage", int(session.get(OID_DISK_USAGE).value)).time(datetime.datetime.utcnow(), WritePrecision.NS)

        write_api.write(INFLUXDB_BUCKET, INFLUXDB_ORGANIZATION, point)
        time.sleep(5)
                
    except KeyboardInterrupt:
        print('flushing data...')
        break


# CLEANING BUCKET
start = "1970-01-01T00:00:00Z"
stop = "2021-07-01T00:00:00Z"
delete_api.delete(start, stop, '_measurement="sys"', bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORGANIZATION)
print('closing...')
time.sleep(1)
client.close()


