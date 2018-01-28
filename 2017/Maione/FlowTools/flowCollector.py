'''
Created on 12 set 2017
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
from scapy.layers import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import gc


class FlowCollector(object):
    '''
    classdocs
    '''
    
    collector={}
    verb=False

    def __init__(self,verbose=False):
        '''
        Constructor
        '''
        self.collector={}
        self.verb=verbose
        
        
    def getFlowKey(self, pkt):
        '''
        Produce a Key to identify a Flow of the packet. Key is a Tuple, containing one or more fields
        It use: Ether.type + IPv4.proto(if there is) + IPv6.flow(if there is) + IPv4/IPv6 Addresses src and dst(if there are) + TCP/UDP Ports src and dst(if there are)
        Otherwise, use packet.sommary() metod(from scapy), to generate it
        '''
        if(pkt):
            if(pkt.haslayer(Ether)):
                key = ((pkt[Ether].type),)
            
            if(pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                key = key + (pkt[1].dst,) + (pkt[1].src,)
                
                if(pkt.haslayer(IP)):
                    key = key + (pkt[IP].proto,)
                elif(pkt.haslayer(IPv6)):
                    key = key + (pkt[IPv6].fl,)
                
                if(pkt.haslayer(TCP)):
                    key = key + (pkt[TCP].dport,) + (pkt[TCP].sport,)
                elif(pkt.haslayer(UDP)):
                    key = key + (pkt[UDP].dport,) + (pkt[UDP].sport,)
                else:
                    key = (pkt.summary(),)
            else:
                key=(pkt.summary(),)
                
            return key
        else:
            return None
    
    def add(self, pkt):
        '''
            Create a new flow istance into the structure, if there are not any with his key; otherwise, increment a counter of hits relative flow +1
            If verbose was True on costructor metod, on '+1' return string: "Flow: +key+ : new packet -> +pkt.summary()+"

        '''
        if(pkt):
                
            key=self.getFlowKey(pkt)
            if(key in self.collector):
                self.collector[key]+=1
                if(self.verb):
                    return "Flow: " + str(key) + ": new packet -> "+str(pkt.summary())
                else:
                    return ""
            else:
                self.collector[key]=1
                return "New Flow: " + str(key) + "\n     First Packet -> " + str(pkt.summary())
        else:
            return "Error on add: Packet not Identitfied -> " + str(pkt)
    
    def getFlows(self,key=None, pkt=None, ipv4=None,ipv6=None, proto=None):
        '''
        Search a Flow/Flows with given key or pkt, IPv4 or IPv6 adress, or Protocol, using his key
        It use ONLY one argument to find Flow, in order: key -> pkt -> IPv4 -> IPv6 -> Protocol
        Return a String with find flows
        '''
        flowsStr = "Flow Found: "
        if(key or pkt):             # Generate or use key to detect a flow
            if(key==None):
                key=self.getFlowKey(pkt)
                
            if(key in self.collector):
                flowsStr+=("\n     *** " + str(key))
                return flowsStr
            else:
                return flowsStr + "Not found"
        elif(ipv4):                 # Find all flows that contains ipv4 address, using elements in the key
            for key_tup in self.collector:
                if(ipv4 in key_tup):
                    flowsStr+="\n     *** " + str(key_tup)
            return flowsStr
        elif(ipv6):                 # Find all flows that contains ipv6 address, using elements in the key
            for key_tup in self.collector:
                if(ipv6 in key_tup):
                    flowsStr+="\n     *** " + str(key_tup)
            return flowsStr
        elif(proto):                # Find all flows that use proto protocol, using elements in the key
            for key_tup in self.collector:
                for el in key_tup:
                    if(proto in str(el)):
                        flowsStr+="\n     *** " + str(key_tup)
        else:
            return flowsStr + " Not Found "
    
    
    
    def biggestFlow(self):
        max = 0
        biggest=None
        for key in self.collector:
            if(max<self.collector[key]):
                max=self.collector[key]
                biggest=key
        return "Biggest Flow: " + str(key) + " with -> " + str(max) + " Packets"
    
    def show(self):
        '''
        Print all flows collected with number of packet that compose it
        '''
        for key in self.collector:
            print "***Flow Key: " + str(key) + "\n        Packets count: " + str(self.collector[key])
            