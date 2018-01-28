'''
Created on 09 set 2017
   
    Copyright (C) 2017  Edoardo Maione edoardo.maione@gmail.com
   
    IdentifyFlow is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    IdentifyFlow is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    see <http://www.gnu.org/licenses/>.

@author: edoardo maione
'''
import scapy
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from FlowTools.flowCollector import FlowCollector
from scapy.layers.inet6 import IPv6
import sys


capLen = 100
if __name__ == '__main__':
    
    v=False
    
    for opt in sys.argv:
        if('-v' in opt ):
            v=True
        else:
            v=False
    
    
    pkts = sniff(count=capLen)
    print pkts
    print "/-------------------------/"
    
    flowTab = FlowCollector(verbose=v)
    
    for p in pkts:
        print flowTab.add(p)
        #pkts.remove(p)
    
    
    
    print "/-------------------------/"
    flowTab.show()
    
    print ''
    #Tests with random adresses and pkts take in pkts
    indIPv4=None
    indIPv6=None
    tPkt=None
    tKey=None
    tProto=random.choice(['TCP','UDP','DHCP','DNS','ARP','ICMP'])
    for p in pkts:
        if p.haslayer(IP):
            if(indIPv4 and random.random()<0.3):
                indIPv4=p[IP].src
            elif not indIPv4:
                indIPv4=p[IP].src
            
        elif p.haslayer(IPv6):
            if(indIPv6 and random.random()<0.5):
                indIPv6=p[IPv6].src
            elif not indIPv6:
                indIPv6=p[IPv6].src
                
        if(random.random()<0.1):
            tKey=flowTab.getFlowKey(p)
        elif not tKey:
            tKey=flowTab.getFlowKey(p)
        
        if(random.random()<0.1):
            tPkt=p
        elif not tPkt:
            tPkt=p
        pkts.remove(p)
    
    print "/----------------------------------/"    

    print "Test getFlows with " + str(indIPv4)
    print flowTab.getFlows(ipv4=indIPv4)
    print "/-------------------------/"
    
    print "Test getFlows with " + str(indIPv6)
    print flowTab.getFlows(ipv6=indIPv6)
    print "/-------------------------/"
    
    print "Test getFlows with " + str(tKey)
    print flowTab.getFlows(key=tKey)
    print "/-------------------------/"
    
    print "Test getFlows with " + tPkt.summary()
    print flowTab.getFlows(pkt=tPkt)
    print "/-------------------------/"
    
    print "Test getFlows with " + tProto
    print flowTab.getFlows(proto=tProto)
    print "/-------------------------/"
    
    print "Test Biggest Flow "
    print flowTab.biggestFlow()
    print "/-------------------------/"
    
    
    pass