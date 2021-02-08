## Developed by Matteo Fantozzi

from easysnmp import Session
from easysnmp import snmp_get
import sys
import datetime
import time
from time import sleep
import rrdtool
import os



## Pharsing input arguments
def printUsage():
    print("Usage: snmp_win_monitor.py [hostname] [community]")
    print("----> Where [hostname] is the host you want to monitor")
    print("----> Where [communuty] is the communuty name of the host")
    
if(len(sys.argv)  < 3 ):
     print("Invalid arguments")
     printUsage()
     exit(1)
   
elif(len(sys.argv)  > 3 ):
     print("Invalid arguments")
     printUsage()
     exit(1)

hostname = sys.argv[1]
community = sys.argv[2]
version = 2
     
if(len(hostname) < 1 ):
     print("Invalid arguments")
     printUsage()
     exit(1)
     
elif(len(community) < 1):
     print("Invalid arguments")
     printUsage()
     exit(1)
 
     
########### FUNCTIONS ############
    
##### GENERAL SYSTEM INFO

## Return system description
def getSysDescr(session):
   sysD = session.get("sysDescr.0")
   return sysD.value

## Return system date
def getUptime(session):
    upTime = session.get("hrSystemUptime.0")
    return datetime.datetime.now() + datetime.timedelta(microseconds= int(upTime.value)/10)
    
## Return system user"s number
def getSysUsersNumber(session):
    userNum = session.get("hrSystemNumUsers.0")
    return userNum.value

## Return system active processes   
def getSysProcesses(session):
    sysProcesses = session.get("hrSystemProcesses.0")
    return sysProcesses.value
     
####### SYSTEM"S MEMORY INFO

## Return system hard drive total capacity in Gb
def getSysStorageDisk(session):
    sys1 = session.get("hrStorageSize.1")
    unit1 = session.get("hrStorageAllocationUnits.1")
    return round(((int(sys1.value) * int(unit1.value))/1073741824),3)
   
# Return systemRam capacity in Gb
def getSysRam(session): 
    sys3 = session.get("hrStorageSize.3")
    unit3 = session.get("hrStorageAllocationUnits.3")
    return round(((int(sys3.value) * int(unit3.value))/1073741824),3)
     
## Return system hard Drive occupied memory in Gb
def getSysOccupiedDiskMemory(session): 
    used = session.get("hrStorageUsed.1")
    unit1 = session.get("hrStorageAllocationUnits.1")
    return round((int(used.value)* int(unit1.value))/1073741824,3)
        
## Return system RAM occupied memory in Gb
def getSysOccupiedRAM(session):
    used = session.get("hrStorageUsed.3")
    unit3 = session.get("hrStorageAllocationUnits.3")
    return round((int(used.value) * int(unit3.value))/1073741824,3)

## Return system Free Ram in Gb
def getSysFreeRam(session):
    total = getSysRam(session)
    used = getSysOccupiedRAM(session)
    return round(total - used,3)

################################# OPERATIVE PART ###########################

## Open session for requests
try:
    session = Session(hostname=hostname, community=community, version=version)

except:
    print("Fatal error, cannot open session, please try again")
    exit(1)
 
## Check if the graphs path exist, if not create dir
if (os.path.isdir("reports")) == False:
    os.mkdir("reports")
    
## Print info
print("Start COLLECTING DATA at: ", hostname," ",getSysDescr(session))
print("---> System users number: ", getSysUsersNumber(session) )
print ("---> System date : ", getUptime(session))
totRam = getSysRam(session)
print("---> Total system Ram: ", totRam," Gb")   
print("---> Total system storage drive: ", getSysStorageDisk(session)," Gb")
print("---> Occupied system storage: ", getSysOccupiedDiskMemory(session)," Gb")
    
   
print("---> For checking processes, busy Ram and free Ram in real time open the .png files with associated names in reports/ ") 
print("+++++++++++++++ To stop collecting press: Ctrl+c +++++++++++++++")

## Processes rrd data
if (os.path.exists("reports/proc.rrd")) == True:
   os.remove("reports/proc.rrd")
   
rrdtool.create("reports/proc.rrd", "--start", "now", "--step", "2", "RRA:AVERAGE:0.5:1:18", "DS:proc:GAUGE:10:10:2000")
       
## Ram rrd data
if (os.path.exists("reports/ram.rrd")) == True:
    os.remove("reports/ram.rrd")
    
rrdtool.create("reports/ram.rrd", "--start", "now", "--step", "2", "RRA:AVERAGE:0.5:1:18", "DS:ram:GAUGE:10:1:"+ str(totRam))
   
## Virtual memory rrd data
if (os.path.exists("reports/freeRam.rrd")) == True:
    os.remove("reports/freeRam.rrd")
    
rrdtool.create("reports/freeRam.rrd", "--start", "now", "--step", "2", "RRA:AVERAGE:0.5:1:18", "DS:freeRam:GAUGE:10:1:"+ str(totRam))
 
while(1):

    ## Collecting data
    try:
        nproc = getSysProcesses(session)
        nram = getSysOccupiedRAM(session)
        oram = getSysFreeRam(session)
    except:
        print("Cannot retreive data, please check te connection and try again")
        exit(1)
        
  
    ## Graph for processes
    rrdtool.update("reports/proc.rrd","N:"+ str(nproc))
    rrdtool.graph("reports/process_graph.png","--start","now-30sec","--end","now","DEF:in=reports/proc.rrd:proc:AVERAGE","LINE:in#0000ff:Active and loaded process")
    
    ## Graph for busy Ram   
    rrdtool.update("reports/ram.rrd","N:"+ str(nram))
    rrdtool.graph("reports/ram_graph.png","--start","now-30sec","--end","now","DEF:in=reports/ram.rrd:ram:AVERAGE","LINE:in#ff1203:Used Ram in Gb")
   
    ## Graph for free Ram
    rrdtool.update("reports/freeRam.rrd","N:"+ str(oram))
    rrdtool.graph("reports/freeRam_graph.png","--start","now-30sec","--end","now","DEF:in=reports/freeRam.rrd:freeRam:AVERAGE","LINE:in#00ff00:Free Ram in Gb")
 
    ## For not flood of requestes the agent sleep some seconds
    time.sleep(2)






