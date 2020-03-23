#!/usr/bin/python3

#
# Documentation
# https://github.com/lucaderi/sgr/tree/master/2020/Maio
#
# Installation
# pip3 install easysnmp

# Import
import time
from easysnmp import Session
from easysnmp import snmp_get
from easysnmp import exceptions as exce

# Parameters

community      = "public"
host           = "localhost"
version        = 1
num_processors = 4

#####################################################

try:
    # Create an SNMP session to be used for all our requests.
    session = Session(hostname=host,community=community,version=version)

    # Continuous loop stopped for 5 seconds after each iteration.
    while True:
        # Revenue number of ticks.
        ticks = session.get('ssCpuRawIdle.0')
        ticksReal = int(ticks.value) * num_processors
        print("The number of ticks spent idle, for " + str(num_processors) + " processors: " + str(ticksReal))

        # Revenue value of available memory.
        memAvail = session.get('memAvailReal.0')
        print("Available memory: " + str(memAvail.value) + " kb")

        # Revenue value of total memory.
        memTot = session.get('memTotalReal.0')
        print("Total memory: " + str(memTot.value) + " kb")

        print("-------------------------------------------------------------")

        # Wait 5 seconds.
        time.sleep(5)
except exce.EasySNMPError as error:
    print(error)
    print('During connection to host '+host)

#####################################################
