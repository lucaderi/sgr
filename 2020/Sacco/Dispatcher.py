#Traffic flow
#!Author: Sacco Giuseppe

from threading import Thread, Lock, Condition
from scapy.all import *



class Dispatcher(Thread):
    def __init__(self, circbuffer, pkt_str, ipaddress):
        threading.Thread.__init__(self)
        self.term = threading.Event()
        self.circbuffer = circbuffer
        self.pkt_str = pkt_str
        self.ownIP = ipaddress

    #its purpose is to take the packet form the buffer, analyze it and separe the 
    # varius packet information and store it in a dictionary.
    #Finally it inserts the packet in a list of dictionaries with mutal exclusion.
    def run(self):
        while not self.term.is_set():
            self.circbuffer._mutex.acquire()
            while len(self.circbuffer.packets) == 0 and not self.term.is_set():
                self.circbuffer._mutex.wait()
            if (not self.term.is_set()):
                pkt = self.circbuffer.retrieve()
                self.circbuffer._mutex.release()

                formatPacket = self.pkt_str.pktStyle.copy()
                formatPacket['bytes'] = int(len(pkt))

                if pkt.haslayer(TCP):
                    formatPacket['protocol'] = "TCP"
                    formatPacket['IP src'] = pkt[IP].src 
                    formatPacket['port src'] = pkt[TCP].sport
                    formatPacket['IP dst'] = pkt[IP].dst
                    formatPacket['port dst'] = pkt[TCP].dport
                    if self.ownIP == pkt[IP].src: 
                        formatPacket['in/out']='out'
                    elif self.ownIP == pkt[IP].dst: 
                        formatPacket['in/out']='in'
                elif pkt.haslayer(UDP):
                    formatPacket['protocol'] = "UDP"
                    formatPacket['IP src'] = pkt[IP].src 
                    formatPacket['port src'] = pkt[UDP].sport
                    formatPacket['IP dst'] = pkt[IP].dst
                    formatPacket['port dst'] = pkt[UDP].dport
                    if self.ownIP == pkt[IP].src: 
                        formatPacket['in/out']='out'
                    elif self.ownIP == pkt[IP].dst: 
                        formatPacket['in/out']='in'
                else : 
                    self.protocol="unknown"

                with self.pkt_str._lockPkts:
                    self.pkt_str.insertPkt(formatPacket)
                    self.pkt_str._lockPkts.notify()