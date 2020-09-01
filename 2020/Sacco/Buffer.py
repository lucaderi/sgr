#Traffic flow
#!Author: Sacco Giuseppe

from threading import Lock, Condition
from scapy.all import *



class Buffer:
    #Initialization
    def __init__(self):
        self.packets = []
        self._mutex = Condition()

    #Append an element
    def add(self, new_p):
        self.packets.append(new_p)

    #Get element by len, relative to the current len
    def retrieve(self):
        pkt = self.packets.pop(0)
        return pkt
