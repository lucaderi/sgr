# SYSTEM RESOURCES MONITOR
# Launch this script for desired time and terminate the monitoring with ctrl+c
# point your browser on localhost:8888 to see the Chronograf dashboard
# join @InfluxdbNotyfy_bot for receiving alerts due resources overload (change chatID value)
# graphs are saved to ./Analytics/somegraph.png

# IMPORTANT: this program requires InfluxDB, Chronograph and Kapacitor services active (from InfluxData)

from influxdb import InfluxDBClient
import datetime
import time
import os
from easysnmp import Session
import webbrowser as web
import matplotlib.pyplot as pl


# snmp constants
HOSTNAME = 'localhost'
COMMUNITY = 'public'
OID_RAM_UNUSED = 'iso.3.6.1.4.1.2021.4.11.0'
OID_DISK_USAGE = 'iso.3.6.1.4.1.2021.9.1.9.1'
OID_CPU_USAGE = 'iso.3.6.1.2.1.25.3.3.1.2' # ...1.2.core_number

URL_DASHBOARD = 'http://localhost:8888'
DB_NAME = 'system'
GRAPHICS_PATH = './Analytics'

# Initializing snmp session
session = Session(hostname=HOSTNAME, community=COMMUNITY, version=2)

# Initializing database
client = InfluxDBClient(HOSTNAME, 8086, 'admin', '1234', DB_NAME)
client.create_database(DB_NAME)

# Open dashboard automatically
web.open_new_tab(URL_DASHBOARD)

print('Running...')
print('Press ctrl+c to stop monitoring and view results.')

while True:
    entry = []
    cpus = session.walk(OID_CPU_USAGE)
    nCores = len(cpus)
    load_sum = 0
    for c in cpus:
        load_sum += int(c.value)
    # print(f'DEBUG >> n. cores: {nCores} tot load: {load_sum}')
    try:
        payload = {
                    'measurement' : 'sysMonitor',
                    'tags': {
                        'device' : 'raspberry'
                        },
                    'time': datetime.datetime.utcnow(),
                    'fields': {
                        'availableram' : int(session.get(OID_RAM_UNUSED).value),
                        'cpuUsage_AVG' : int(load_sum/nCores),
                        'disk_usage' : int(session.get(OID_DISK_USAGE).value)
                        }
        }
        entry.append(payload)
        client.write_points(entry)
        time.sleep(10)
                
    except KeyboardInterrupt:
        print('closing...')
        break


# Query from database
query = client.query('SELECT * FROM "system"."autogen"."sysMonitor"')

# Lists for saving query results
time = []
ramY = []
cpuY = []
diskY = []

for p in query.get_points():
    time.append(p['time'])
    ramY.append(int(p['availableram']))
    cpuY.append(int(p['cpuUsage_AVG']))
    diskY.append(int(p['disk_usage']))
    
    
'''                   GENERATING LOCAL GRAPHIC REPORTS           '''

# Create graphics directory
if not os.path.exists(GRAPHICS_PATH):
        os.makedirs(GRAPHICS_PATH)


# RAM                             
pl.plot(time, ramY, 'mediumslateblue')
pl.ylim(0, 1000000)
pl.xticks(time, '')
pl.xlabel('Time')
pl.ylabel('KB')
pl.suptitle('AVAILABLE RAM')
pl.savefig(f'{GRAPHICS_PATH}/ram', format='pdf')
pl.show()

# CPU AVERAGE CORES LOAD
pl.plot(time, cpuY,)
pl.ylim(0, 100)
pl.xticks(time, '')
pl.xlabel('Time')
pl.ylabel('%')
pl.suptitle('CPU AVERAGE LOAD')
pl.savefig(f'{GRAPHICS_PATH}/cpu', format='pdf')
pl.show()

# HDD USED SPACE   
pl.plot(time, diskY,'green')
pl.ylim(0, 100)
pl.xticks(time, '')
pl.xlabel('Time')
pl.ylabel('%')
pl.suptitle('HARD DISK USAGE (%)')
pl.savefig(f'{GRAPHICS_PATH}/hdd', format='pdf')
pl.show()

# CLEANING DATA
client.drop_database(DB_NAME)

