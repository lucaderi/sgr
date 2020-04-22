#!/usr/bin/python3

#
# Documentation
# https://github.com/lucaderi/sgr/tree/master/2020/Maio
#
# Installation
# pip3 install easysnmp
# pip3 install rrdtool

# Import
import time
import os
from easysnmp import Session
from easysnmp import snmp_get
from easysnmp import exceptions as exce
import rrdtool

# Parameters

community      = "public"
host           = "localhost"
version        = 1
#####################################################

# Create the .rrd file for the cpu percentage
if os.path.isfile("cpu.rrd") == False: 
    rrdtool.create('cpu.rrd','--step','5','DS:cpu:GAUGE:6:0:100', 'RRA:AVERAGE:0.5:1:720',)

try:
    # Create an SNMP session to be used for all our requests.
    session = Session(hostname=host,community=community,version=version)
    
    # Create the .rrd file for the memory data
    if os.path.isfile("memCheck.rrd") == False:
        rrdtool.create('memCheck.rrd',  '--step', '5', 'DS:mem:GAUGE:6:0:'+str(session.get('memTotalReal.0').value),'RRA:AVERAGE:0.5:1:720')
    
    start = os.popen('date +%s').read()
    
    # Continuous loop stopped for 5 seconds after each iteration.
    while True:

        # Revenue % usage CPU
        perc = session.get('ssCpuIdle.0')
        print("CPU usage: "+str(perc.value)+"%")

        # Calculate % available CPU
        percAvail = 100 - int(perc.value)
        print("Free CPU: "+str(percAvail)+"%")

        # Revenue number of ticks.
        ticks = session.get('ssCpuRawIdle.0')
        num_processors = session.get('ssCpuNumCpus.0')
        ticksReal = int(ticks.value) * int(num_processors.value)
        print("The number of ticks spent idle, for " + str(num_processors.value) + " processors: " + str(ticksReal))

        # Revenue value of available memory.
        memAvail = session.get('memAvailReal.0')
        print("Available memory: " + str(memAvail.value) + "kb")

        # Revenue value of total memory.
        memTot = session.get('memTotalReal.0')
        print("Total memory: " + str(memTot.value) + "kb")

        print("-------------------------------------------------------------")

        # Update the .rrd files and prints the graphs
        usedMeM = int(memTot.value) - int(memAvail.value)
        rrdtool.update('memCheck.rrd', 'N:' + str(usedMeM))
        rrdtool.update('cpu.rrd', 'N:' + str(perc.value))
        rrdtool.graph("memCheckGraph.png","--start","now-5min","--end","now", "DEF:in=memCheck.rrd:mem:AVERAGE", "CDEF:mem_U=in,1024,*" ,"AREA:mem_U#ff1203:MemUsedReal")
        rrdtool.graph("cpuGraph.png","--start","now-5min","--end","now","DEF:in=cpu.rrd:cpu:AVERAGE","AREA:in#ff1203:CPUusedReal")

        # Wait 5 seconds.
        time.sleep(5)
    

except exce.EasySNMPError as error:
    print(error)
    print('During connection to host '+host)

#####################################################
