#!/usr/bin/env python3

#Traffic flow
#!Author: Sacco Giuseppe

from scapy.all import *
from threading import Thread, Lock
import socket
import netifaces as ni

from Dispatcher import Dispatcher
from PortScanner import PortScanner
from Visual import Visual
from Buffer import Buffer
from Pkt import PacketsStr


#packet handler
def traffic_handler(pkt):
    global buff
    with buff._mutex: 
        buff.add(pkt)
        buff._mutex.notify()

#-------------------------------------------------------------------------------------------#

def main():
    #interface on which capture packets 
    interface = input('interface: ') 
    if len(interface )== 0 :
        print('Not valid interface.')
        sys.exit()
        
    #own ip
    ipaddress = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

    #-------------------------------------------------------------------------------------------#
    #two data structure used to analyze packets and store the flows
    global buff
    buff = Buffer()
    pkt_str = PacketsStr()

    #threads used to analyze the flows and their content
    dispatcher = Dispatcher(buff, pkt_str, ipaddress)
    scanner = PortScanner(pkt_str)
    visual = Visual(pkt_str)

    dispatcher.start()
    scanner.start()
    visual.start()

    #starting to sniff packets
    capture = sniff(filter='ip', session=IPSession, prn=traffic_handler, count=0, iface=interface)

    #at the and of the sniff, when Ctrl+C key is pressed, termination variable is set to notify threads
    dispatcher.term.set()
    scanner.term.set()
    visual.term.set()

    #to wake the threads which are waiting for new packets
    time.sleep(1)
    with buff._mutex:
        buff._mutex.notify()

    with pkt_str._lockPkts:
        pkt_str._lockPkts.notify()


    dispatcher.join()
    scanner.join()
    visual.join()

    #print some information about the number of unknown and known packets
    print("\nUnknown packets: %d" % len(pkt_str.unknown))
    print("Packets of unknown process: %d" % len(pkt_str.unanalizedPkt))
    print("Total packets: %d" % len(capture))
    

if __name__ == "__main__":
    main()