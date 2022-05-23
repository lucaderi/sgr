from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from easysnmp import Session, snmp_get, exceptions
import sys
import time
import math
from configFile import *

#SNMP config values and OIDS
HOSTNAME = 'localhost'
COMMUNITY = 'public'
RAM_USAGE_OID = '1.3.6.1.4.1.2021.4.6.0'
RAM_TOTAL_OID = '1.3.6.1.4.1.2021.4.5.0'
DISK_USAGE_OID = 'hrStorageUsed'
CPU_USAGE_OID = 'hrProcessorLoad'
DISK_DESCR_OID = 'hrStorageDescr'
DISK_TOTAL_OID = 'hrStorageSize'

#Establishing SNMP session
session = Session(hostname=HOSTNAME, community=COMMUNITY, version=2)

#Connecting to InfluxDB
client=InfluxDBClient(url="http://localhost:8086", token=token, org=org)
write_api=client.write_api(write_options = SYNCHRONOUS)
delete_api = client.delete_api()

#Values for double exponential smoothing and deviation calculations
alpha = 0.5
beta = 0.5
rho = 0.5

#RAM variables
ramPrevLevel = 0
ramLevel = 0
ramTrend = 0
ramSumError = 0
ramLowBound = 0
ramHighBound = 999999999999
ramTotal = int(session.get(RAM_TOTAL_OID).value)
ramValues = [int(session.get(RAM_USAGE_OID).value)]

#Gets a description of all the storages detected
diskDescr = session.walk(DISK_DESCR_OID)

#Gets the average use of each cpu core
cpuWalk = session.walk(CPU_USAGE_OID)

diskOID = ''

print('Storages detected:')
for d in diskDescr:
  print(d.value)

while diskOID == '':
  storName = input('Which storage do you want to monitor? ')
  for d in diskDescr:
    if(d.value == storName):
      diskOID=d.oid_index
  if diskOID == '':
    print('No such storage found')

#DISK values
diskCompleteOID = (DISK_USAGE_OID + '.' + diskOID)
diskTotal = int(session.get(DISK_TOTAL_OID + '.' + diskOID).value)
diskValues = [int(session.get(diskCompleteOID).value)]
diskPrevLevel = 0
diskLevel = 0
diskTrend = 0
diskSumError = 0
diskLowBound = 0
diskHighBound = 999999999999

#CPU values
totalCPUload=0
for c in cpuWalk:
  totalCPUload+=int(c.value)
avgCPUload = totalCPUload/len(cpuWalk)  #The average usage across all detected cores
cpuValues = [avgCPUload]
cpuPrevLevel = 0
cpuLevel = 0
cpuTrend = 0
cpuSumError = 0
cpuLowBound = 0
cpuHighBound = 999999999999

#Initialization
ramPrediction = [ramValues[0]]
diskPrediction = [diskValues[0]]
cpuPrediction = [cpuValues[0]]

n = 1
frequencyValue = 'a'
while isinstance(frequencyValue, int) == False:
  try:
    frequencyValue = int(input('How often (in seconds) should the program run snmp commands?(Input an integer, default:2) '))
  except ValueError:
    print("Input needs to be a number")

print('Currently monitoring, press ctrl+c to stop...')
while True:
  try:
    if n<2:
      #This block is run only once, at the beginning (n=1)
      totalCPUload=0
      cpuWalk = session.walk(CPU_USAGE_OID)
      for c in cpuWalk:
        totalCPUload+=int(c.value)
      avgCPUload = totalCPUload/len(cpuWalk)

      #Read and append new values from SNMP
      cpuValues.append(avgCPUload)
      ramValues.append(int(session.get(RAM_USAGE_OID).value))
      diskValues.append(int(session.get(diskCompleteOID).value))

      n=n+1
    else:
      if n==2:
        #This block is run only once (second "while" cycle)
        #Initializes these variables
        ramLevel, ramTrend = int(ramValues[0]), int(ramValues[1]) - int(ramValues[0])
        diskLevel, diskTrend = int(diskValues[0]), int(diskValues[1]) - int(diskValues[0])
        cpuLevel, cpuTrend = int(cpuValues[0]), int(cpuValues[1]) - int(cpuValues[0])
        n=n+1

      totalCPUload=0
      cpuWalk = session.walk(CPU_USAGE_OID)
      for c in cpuWalk:
        totalCPUload+=int(c.value)
      avgCPUload = totalCPUload/len(cpuWalk)

      #Read and append new values from SNMP
      cpuValues.append(avgCPUload)
      ramValues.append(int(session.get(RAM_USAGE_OID).value))
      diskValues.append(int(session.get(diskCompleteOID).value))

      #Double exponential smoothing to predict the next value; result is appended to the Prediction lists
      #RAM
      ramPrevLevel = ramLevel
      ramLevel = alpha*ramValues[-1] + (1-alpha)*(ramPrevLevel+ramTrend)
      ramTrend = beta*(ramLevel-ramPrevLevel) + (1-beta)*ramTrend
      ramPrediction.append(ramLevel + ramTrend)

      #DISK
      diskPrevLevel = diskLevel
      diskLevel = alpha*diskValues[-1] + (1-alpha)*(diskPrevLevel+diskTrend)
      diskTrend = beta*(diskLevel-diskPrevLevel) + (1-beta)*diskTrend
      diskPrediction.append(diskLevel + diskTrend)

      #CPU
      cpuPrevLevel = cpuLevel
      cpuLevel = alpha*cpuValues[-1] + (1-alpha)*(cpuPrevLevel+cpuTrend)
      cpuTrend = beta*(cpuLevel-cpuPrevLevel) + (1-beta)*cpuTrend
      cpuPrediction.append(cpuLevel + cpuTrend)

      if len(ramPrediction)>2:

        #High Bound/Low Bound calculations
        #RAM
        for index in range(len(ramValues)-1):
          ramSumError += (ramValues[index] - ramPrediction[index])**2
        deviation = math.sqrt(ramSumError / (len(ramValues) + 1))
        confidence = deviation * rho
        ramLowBound=round((ramPrediction[-3] - confidence),3)
        ramHighBound=round((ramPrediction[-3] + confidence),3)

        #DISK
        for index in range(len(diskValues)-1):
          diskSumError += (diskValues[index] - diskPrediction[index])**2
        deviation = math.sqrt(diskSumError / (len(diskValues) + 1))
        confidence = deviation * rho
        diskLowBound=round((diskPrediction[-3] - confidence),3)
        diskHighBound=round((diskPrediction[-3] + confidence),3)

        #CPU
        for index in range(len(cpuValues)-1):
          cpuSumError += (cpuValues[index] - cpuPrediction[index])**2
        deviation = math.sqrt(cpuSumError / (len(cpuValues) + 1))
        confidence = deviation * rho
        cpuLowBound=round((cpuPrediction[-3] - confidence),3)
        cpuHighBound=round((cpuPrediction[-3] + confidence),3)
        

        #InfluxDB writes
        #RAM
        point = Point("ramMonitor") \
        .tag("host", "host1") \
        .field("Ram Usage", ramValues[-1]) \
        .field("Ram Percent Usage", 100/ramTotal * ramValues[-1]) \
        .field("Next Value Prediction", int(ramPrediction[-1])) \
        .field("Lower Bound", int(ramLowBound)) \
        .field("Higher Bound", int(ramHighBound)) \
        .time(datetime.utcnow(), WritePrecision.NS)
        write_api.write(bucket, org, point)

        #DISK
        point = Point("diskMonitor") \
        .tag("host", "host1") \
        .field("Disk Usage", diskValues[-1]) \
        .field("Disk Percent Usage", 100/diskTotal * diskValues[-1]) \
        .field("Next Value Prediction", int(diskPrediction[-1])) \
        .field("Lower Bound", int(diskLowBound)) \
        .field("Higher Bound", int(diskHighBound)) \
        .time(datetime.utcnow(), WritePrecision.NS)
        write_api.write(bucket, org, point)

        #CPU
        point = Point("cpuMonitor") \
        .tag("host", "host1") \
        .field("CPU Percent Usage", cpuValues[-1]) \
        .field("Next Value Prediction", int(cpuPrediction[-1])) \
        .field("Lower Bound", int(cpuLowBound)) \
        .field("Higher Bound", int(cpuHighBound)) \
        .time(datetime.utcnow(), WritePrecision.NS)
        write_api.write(bucket, org, point)

        #endif
    time.sleep(frequencyValue)
  except KeyboardInterrupt:

        #InfluxDB optional cleanup

        deleteChoice = input('\nWould you like to clear the database?(y/n) ')
        if deleteChoice == 'y':
          start = "1970-01-01T00:00:00Z"
          stop = datetime.utcnow()
          delete_api.delete(start, stop, '_measurement="ramMonitor"', bucket=bucket, org=org)
          delete_api.delete(start, stop, '_measurement="diskMonitor"', bucket=bucket, org=org)
          delete_api.delete(start, stop, '_measurement="cpuMonitor"', bucket=bucket, org=org)
          time.sleep(1)
          pass
        print('Closing...')
        client.close()
        break
