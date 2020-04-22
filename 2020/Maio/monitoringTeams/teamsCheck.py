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

community = "public"
host = "localhost"
version = 1

#####################################################

# Create the .rrd files for the InOctet and OutOctet counters.
if os.path.isfile("InOctet.rrd") == False:
    rrdtool.create('InOctet.rrd', '--step', '5', 'DS:InOctet:Counter:6:0:U', 'RRA:AVERAGE:0.5:1:720', )

if os.path.isfile("InOctet2.rrd") == False:
    rrdtool.create('InOctet2.rrd', '--step', '5', 'DS:InOctet:Counter:6:0:U', 'RRA:AVERAGE:0.5:1:720', )

if os.path.isfile("OutOctet.rrd") == False:
    rrdtool.create('OutOctet.rrd', '--step', '5', 'DS:OutOctet:Counter:6:0:U', 'RRA:AVERAGE:0.5:1:720', )

if os.path.isfile("OutOctet2.rrd") == False:
    rrdtool.create('OutOctet2.rrd', '--step', '5', 'DS:OutOctet:Counter:6:0:U', 'RRA:AVERAGE:0.5:1:720', )


try:
    # Create an SNMP session to be used for all our requests.
    session = Session(hostname=host, community=community, version=version)

    # Continuous loop stopped for 5 seconds after each iteration.
    while True:

        if os.system("pgrep -x teams") != 256:
            on = True
        else:
            on = False


        InOctet = session.get('ifInOctets.2')
        OutOctet = session.get('ifOutOctets.2')

        # Update the .rrd files and print the graph.

        if on == True:
            rrdtool.update('InOctet2.rrd', 'N:' + str(InOctet.value))
            rrdtool.update('OutOctet2.rrd', 'N:' + str(OutOctet.value))
            print("OutOctet value: "+OutOctet.value +" InOctet value: "+InOctet.value)
        else :
            rrdtool.update('InOctet.rrd', 'N:' + str(InOctet.value))
            rrdtool.update('OutOctet.rrd', 'N:' + str(OutOctet.value))

        rrdtool.graph("teamsTrafficGraph.png", "--start", "now-5min", "--end", "now",
                      "DEF:in1=InOctet.rrd:InOctet:AVERAGE", "DEF:in2=OutOctet.rrd:OutOctet:AVERAGE",
                      "DEF:in3=InOctet2.rrd:InOctet:AVERAGE", "DEF:in4=OutOctet2.rrd:OutOctet:AVERAGE",
                      "CDEF:inOctet1=in1,1024,*", "LINE:inOctet1#0000ff:In Octet when teams is not running",
                      "CDEF:outOctet1=in2,1024,*", "LINE:outOctet1#00ff00:Out Octet when teams is not running",
                      "CDEF:inOctet2=in3,1024,*", "LINE:inOctet2#ff0000:In Octet when teams is running",
                      "CDEF:outOctet2=in4,1024,*", "LINE:outOctet2#8f00ff:Out Octet when teams is not running"
                      )

        # Wait 5 seconds.
        time.sleep(5)


except exce.EasySNMPError as error:
    print(error)
    print('During connection to host ' + host)

#####################################################
