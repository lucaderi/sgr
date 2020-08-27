#Traffic flow
#!Author: Sacco Giuseppe

from scapy.all import *
from threading import Lock, Condition


class PacketsStr:
    #dictionary representing the fields we want to save from a package
    pktStyle={"Name": None, "PID": None, "protocol": None,"bytes": None,"packets": None,"IP src": None,"port src": None,"IP dst": None,"port dst": None, "in/out": None}

    def __init__(self):
        self.pktsInformations = []
        self.unanalizedPkt = []
        self.unknown = []
        self._lockPkts = Condition()
        self.connection = []

    #insert a package or in a unknown package queue or in a queue 
    # that representing the packages not yet analyzed
    def insertPkt(self, pkt):
        if pkt['protocol'] == 'TCP':
            if pkt['in/out'] == None :
                self.unknown.append(pkt)
            else :
                self.unanalizedPkt.append(pkt)
        elif pkt['protocol'] == 'UDP':
            if pkt['in/out'] == None :
                self.unknown.append(pkt)
            else :
                self.unanalizedPkt.append(pkt)        
        else: 
            self.unknown.append(pkt)
        