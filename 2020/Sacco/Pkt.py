#Traffic flow
#!Author: Sacco Giuseppe

from scapy.all import *
from threading import Lock, Condition


class PacketsStr:
    #dictionary representing the fields we want to save from a package
    pktStyle={
        "Name": None, "PID": None, "protocol": None,"bytes": None,
        "packets": None,"IP src": None,"port src": None,"IP dst": None,
        "port dst": None, "in/out": None}

    #dictionary representing a bidirectional flow
    flowStyle={
        "Name": None, "PID": None, "protocol": None, "bytes in": None,
        "bytes out": None, "packets": None,"local IP": None,"local port": None,
        "remote IP": None, "remote port": None, "last update": None
    }

    def __init__(self):
        self.flows = []
        self.unanalizedPkt = []
        self.unknown = []
        self._lockPkts = Condition()

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
        
    #if flow exists then the function update its statistics
    #return: 0 if no flow are matched and 1 if the flow's statistics are updated
    def tryUpdateFlow(self, p, port):
        for i in self.flows :
            if p['in/out'] == 'in':
                if (p['IP src'] == i['remote IP'] and p['port src'] == i['remote port'] 
                    and p['IP dst'] == i['local IP'] and port == i['local port']
                ):
                    length = p['bytes']
                    i['bytes in'] += length
                    i['packets'] += 1
                    i['last update'] = datetime.now()  
                    return 1
            elif p['in/out'] == 'out':
                if (p['IP dst'] == i['remote IP'] and p['port dst'] == i['remote port'] 
                    and p['IP src'] == i['local IP'] and port == i['local port']
                ):
                    length = p['bytes']
                    i['bytes out'] += length
                    i['packets'] += 1
                    insert = 1
                    i['last update'] = datetime.now()
                    return 1

        return 0