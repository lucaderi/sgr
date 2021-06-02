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
OID_CPU_USAGE = 'iso.3.6.1.2.1.25.3.3.1.2'

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
    try:
        payload = {
                    'measurement' : 'sysMonitor',
                    'tags': {
                        'device' : 'raspberry'
                        },
                    'time': datetime.datetime.utcnow(),
                    'fields': {
                        'availableram' : int(session.get(OID_RAM_UNUSED).value),
                        'cpuUsage_C1' : int(session.get(OID_CPU_USAGE+'.196608').value),
                        'cpuUsage_C2' : int(session.get(OID_CPU_USAGE+'.196609').value),
                        'cpuUsage_C3' : int(session.get(OID_CPU_USAGE+'.196610').value),
                        'cpuUsage_C4' : int(session.get(OID_CPU_USAGE+'.196611').value),
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
cpuY1 = []
cpuY2 = []
cpuY3 = []
cpuY4 = []
diskY = []

for p in query.get_points():
    time.append(p['time'])
    ramY.append(int(p['availableram']))
    cpuY1.append(int(p['cpuUsage_C1']))
    cpuY2.append(int(p['cpuUsage_C2']))
    cpuY3.append(int(p['cpuUsage_C3']))
    cpuY4.append(int(p['cpuUsage_C4']))
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

# CPU SINGLE CORES LOAD
fig, fAxes = pl.subplots(ncols=2, nrows=2)

fAxes[0,0].plot(time, cpuY1)
fAxes[0,0].set_ylim([0, 100])
fAxes[0,0].set_title('Core 1')
fAxes[0,0].set_xticklabels([])

fAxes[0,1].plot(time, cpuY2)
fAxes[0,1].set_ylim([0, 100])
fAxes[0,1].set_title('Core 2')
fAxes[0,1].set_xticklabels([])

fAxes[1,0].plot(time, cpuY3)
fAxes[1,0].set_ylim([0, 100])
fAxes[1,0].set_title('Core 3')
fAxes[1,0].set_xticklabels([])

fAxes[1,1].plot(time, cpuY4)
fAxes[1,1].set_ylim([0, 100])
fAxes[1,1].set_title('Core 4')
fAxes[1,1].set_xticklabels([])
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

