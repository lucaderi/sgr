#Traffic flow
#!Author: Sacco Giuseppe

from threading import Thread, Lock, Condition
import threading
#!install with sudo
from tabulate import tabulate
from scapy.all import *
from socket import *
import psutil


class Visual(Thread):
    def __init__(self, pkt_str):
        threading.Thread.__init__(self)
        self.term = threading.Event()
        self.pkt_str = pkt_str

    #This threads is responsible to connect the packets with the process who is 
    # listening on the port specified in the packet. 
    #If there is already a stored packet connected to that process on that port, 
    # then the number of packets is incremented as well as the number of bytes which 
    # belong to that flow.
    def run(self):
        while not self.term.is_set():
            self.pkt_str._lockPkts.acquire()
            while len(self.pkt_str.unanalizedPkt) == 0 and not self.term.is_set():
                self.pkt_str._lockPkts.wait()
            newlist = self.pkt_str.unanalizedPkt.copy()
            self.pkt_str.unanalizedPkt.clear()
            connections = self.pkt_str.connection.copy()
            self.pkt_str._lockPkts.release()

            if not self.term.is_set():
                for p in newlist:
                    insert = 0
                    if p['in/out'] == 'in':
                        port = p['port dst']
                    elif p['in/out'] == 'out':
                        port = p['port src']

                    for i in self.pkt_str.pktsInformations :
                        if i['in/out'] == 'in' and p['in/out'] == 'in':
                            if port == i['port dst']:
                                length = p['bytes']
                                i['bytes'] += length
                                i['packets'] += 1
                                insert = 1
                        elif i['in/out'] == 'out' and p['in/out'] == 'out':
                            if port == i['port src']:
                                length = p['bytes']
                                i['bytes'] += length
                                i['packets'] += 1
                                insert = 1


                    if not insert :
                        t=0
                        i=0
                        c_len = len(connections)
                        while i < c_len and not t :
                            c=connections[i]
                            if port == c.laddr[1]:
                                p['Name'] = psutil.Process(c.pid).name()
                                p['PID'] = c.pid 
                                p['packets'] = 1
                                t=1
                                self.pkt_str.pktsInformations.append(p)
                            i+=1
                        if t == 0: 
                            with self.pkt_str._lockPkts :
                                self.pkt_str.insertPkt(p)
                newlist.clear()

            #-------------------------------------------------------------------------------------------#
            #print information about flows
            subprocess.call('clear', shell=True)
            table = []
            keys = self.pkt_str.pktStyle.keys()

            for i in self.pkt_str.pktsInformations :
                d = i.values()
                table.append(d)                
            
            print(tabulate(table, keys))
            time.sleep(0.5)


