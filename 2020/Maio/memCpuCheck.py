import time
import os
import sys
import subprocess


community = input("Please enter community: ")
host = input("Please enter host name: ")

while True:
    ticks = os.popen('snmpget -v1 -c '+community+' '+host+' '+'ssCpuRawIdle.0').read()
    ticksR = ticks[ticks.index('Counter32:')+11:]
    realTicks = int(ticksR)
    print("The number of ticks spent idle, for 4 processors: ",realTicks*4, "\n")

    memAvail = os.popen('snmpget -v1 -c '+community+' '+host+' '+'memAvailReal.0').read()
    print("Available memory: "+memAvail[memAvail.index('INTEGER:')+9:])

    memTot = os.popen('snmpget -v1 -c '+community+' '+host+' '+'memTotalReal.0').read()
    print("Total memory: "+memTot[memTot.index('INTEGER:')+9:])

    print("-------------------------------------------------------------")
    time.sleep(5)