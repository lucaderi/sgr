#Traffic flow
#!Author: Sacco Giuseppe

from threading import Thread, Lock, Condition
import threading
from tabulate import tabulate
from scapy.all import *
from socket import *
import psutil
from datetime import datetime


class Visual(Thread):
    def __init__(self, pkt_str):
        threading.Thread.__init__(self)
        self.term = threading.Event()
        self.pkt_str = pkt_str
    
    # This threads is responsible to create flows and show it.
    # At each iteration the thread scann all the port to find new 
    # processes activated.
    # When new packets arrive, the thread use the function 
    # "tryUpdateFlows" which update the statistics of the flow with 
    # the information about the packet, if the correspective flow exists.
    # If this flow there isn't then new bidirectional flow is created.
    def run(self):
        keys = self.pkt_str.flowStyle.keys()
        
        while not self.term.is_set():
            self.pkt_str._lockPkts.acquire()
            while len(self.pkt_str.unanalizedPkt) == 0 and not self.term.is_set():
                self.pkt_str._lockPkts.wait()
            newlist = self.pkt_str.unanalizedPkt.copy()
            self.pkt_str.unanalizedPkt.clear()
            self.pkt_str._lockPkts.release()
            connections = psutil.net_connections()

            if not self.term.is_set():
                for p in newlist:
                    insert = 0
                    if p['in/out'] == 'in':
                        port = p['port dst']
                    elif p['in/out'] == 'out':
                        port = p['port src']

                    insert = self.pkt_str.tryUpdateFlow(p, port)

                    if not insert :
                        t=0
                        for c in connections:
                            if port == c.laddr[1]:
                                flow = self.pkt_str.flowStyle.copy()
                                if p['in/out'] == 'in':
                                    flow['Name'] = psutil.Process(c.pid).name()
                                    flow['PID'] = c.pid
                                    flow['protocol'] = p['protocol']
                                    flow['bytes in'] = p['bytes']
                                    flow['bytes out'] = 0
                                    flow['packets'] = 1
                                    flow['local IP'] = p['IP dst']
                                    flow['local port'] = port
                                    flow['remote IP'] = p['IP src']
                                    flow['remote port'] = p['port src']
                                    flow['last update'] = datetime.now()  
                                    self.pkt_str.flows.append(flow)
                                    t=1
                                    break
                                elif p['in/out'] == 'out':
                                    flow['Name'] = psutil.Process(c.pid).name()
                                    flow['PID'] = c.pid
                                    flow['protocol'] = p['protocol']
                                    flow['bytes in'] = 0
                                    flow['bytes out'] = p['bytes']
                                    flow['packets'] = 1
                                    flow['local IP'] = p['IP src']
                                    flow['local port'] = port
                                    flow['remote IP'] = p['IP dst']
                                    flow['remote port'] = p['port dst']
                                    flow['last update'] = datetime.now()  
                                    self.pkt_str.flows.append(flow)
                                    t=1
                                    break

                        if t == 0: 
                            with self.pkt_str._lockPkts :
                                self.pkt_str.insertPkt(p)

                #purge of flows inactive for 15 seconds
                self.pkt_str.flows = [f for f in self.pkt_str.flows 
                    if not (datetime.now() - f['last update']).seconds >= 15
                ]

                newlist.clear()

            #-------------------------------------------------------------------------------------------#
            #print information about flows

            subprocess.call('clear', shell=True)
            table = []

            for i in self.pkt_str.flows :
                d = i.values()
                table.append(d)                
            
            print(tabulate(table, keys))

            time.sleep(0.5)


