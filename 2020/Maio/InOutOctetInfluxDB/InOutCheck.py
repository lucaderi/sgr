#!/usr/bin/python3

#
# Documentation
# https://github.com/lucaderi/sgr/tree/master/2020/Maio
#
# Installation
# pip3 install easysnmp
# pip3 install rrdtool

# Import
import os

from easysnmp import Session
from easysnmp import exceptions as exce
import influxdb_client
from influxdb_client import InfluxDBClient,Point

# Parameters

community = "public"
host = "localhost"
version = 1

#####################################################



try:
    # Create an SNMP session to be used for all our requests.
    session = Session(hostname=host, community=community, version=version)

    client = InfluxDBClient(url="http://localhost:9999", token="biWVynq7z1dZsjNLrmvAP3BJAs8Oo7xTW9-p857l2PlDBTcDIPHfjDHAhpudtPKtVRNKE_nHMZ9mrSeczzkh-A==")

    write_api = client.write_api()
    while True:

        InOctet = session.get('ifInOctets.2')

        #data = "InOctet,host=host1 InOctet="+str(InOctet.value)+" "+str(os.system("date +%s"))

        #write_api.write("InOutOctet", "0590c71673a9d000", data)

        point = Point("system") \
            .tag("location", "Pisa")\
            .field("in", InOctet.value) \
            .time(os.system("date +%s"))

        write_api.write(bucket="InOutOctet",record=point,org='0590c71673a9d000')

        # Update the .rrd files and print the graph.

except exce.EasySNMPError as error:
    print(error)
    print('During connection to host ' + host)

#####################################################