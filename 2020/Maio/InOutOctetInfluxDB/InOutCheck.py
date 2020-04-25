#!/usr/bin/python3

#
# Documentation
# https://github.com/lucaderi/sgr/tree/master/2020/Maio
#
# Installation
# pip3 install easysnmp
# pip3 install influxdb-client

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

        # Revenue InOctet and OutOctet values
        InOctet = session.get('ifInOctets.2')
        OutOctet = session.get('ifOutOctets.2')

        # building Influx measurements
        point = Point("InOctet") \
            .tag("location", "localhost")\
            .field("bytes", int(InOctet.value))

        point2 = Point("OutOctet") \
            .tag("location", "localhost") \
            .field("bytes", int(OutOctet.value))

        # writing on InfluxDB Bucket choosen the values
        write_api.write(bucket="InOutOctet",record=point,org='0590c71673a9d000')
        write_api.write(bucket="InOutOctet", record=point2, org='0590c71673a9d000')

except exce.EasySNMPError as error:
    print(error)
    print('During connection to host ' + host)

#####################################################