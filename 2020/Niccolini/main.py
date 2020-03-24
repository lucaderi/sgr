#!/usr/bin/python3
from pysnmp.hlapi import *
import time

community = 'public'
host = 'localhost'

import sys
if len(sys.argv) == 3:
    community = sys.argv[1]
    host = sys.argv[2]
elif len(sys.argv) != 1:
    print('Inserire community e host, altrimenti nessuno e di default sarannò: '+community+' e '+host)
    exit(1)

def walk():
    # Memoria disponibile
    errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(SnmpEngine(),
                                                                        CommunityData(community),
                                                                        UdpTransportTarget((host, 161)), ContextData(),
                                                                       ObjectType(ObjectIdentity('UCD-SNMP-MIB','memAvailReal', 0))))
    if errorIndication:
        print('Error: '+errorIndication)
        exit(1)
    elif errorStatus:
        print('Error: '+'%s at %s' % (errorStatus.prettyPrint(),
                                      errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        exit(1)
    else:
         mem = varBinds[0].prettyPrint().split("=")[1].strip()
         print("Mem disponibile =\t" + mem + " KB")

    # Memoria totale
    errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(SnmpEngine(),
                                                                CommunityData(community),
                                                                UdpTransportTarget((host, 161)), ContextData(),
                                                                ObjectType(ObjectIdentity('UCD-SNMP-MIB', 'memTotalReal', 0))))
    if errorIndication:
        print('Error: ' + errorIndication)
        exit(1)
    elif errorStatus:
        print('Error: ' + '%s at %s' % (errorStatus.prettyPrint(),
                                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        exit(1)
    else:
        mem = varBinds[0].prettyPrint().split("=")[1].strip()
        print("Mem totale =\t" + mem + " KB")

    # CPU
    errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(SnmpEngine(),
                                                                        CommunityData(community),
                                                                        UdpTransportTarget((host, 161)), ContextData(),
                                                                        ObjectType(ObjectIdentity('UCD-SNMP-MIB', 'ssCpuIdle', 0))))
    if errorIndication:
        print('Error: '+errorIndication)
        exit(1)
    elif errorStatus:
         print('Error: '+'%s at %s' % (errorStatus.prettyPrint(),
                                       errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
         exit(1)
    else:
         cpu = varBinds[0].prettyPrint().split("=")[1].strip()
         print("uso CPU =\t\t" + cpu + "%")
    print('------------------')

while True:
    walk();
    time.sleep(5)