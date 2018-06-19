# encoding=utf8 
# autore: Salvatore Costantino
# mail: s.costantino5@studenti.unipi.it

from FlowEntry import *
from AbstractFlowTable import *

class SimpleFlowTable(AbstractFlowTable):
    """
        overview:   HashTable di flussi relativi a chiamate TCP connect()/TCP accept() 
                    chiave composta dai seguenti attrributi:
                        1)pid: PID del processo chiamante
                        2)comm: nome processo chiamante
                        3)ip: versione IP
                        4)sAddr: indirizzo IP sorgente
                        5)dAddr: indirizzo IP destinazione
                        6)port: porta remota (se TCP connect()) o porta locale (se TCP accept())
        
        attributes: (ereditati dalla classe base, AbstractFlowTable)
    """

    def _linkNewEntry(self,pid,comm,ip,sAddr,dAddr,port,head): 
        entry=FlowEntry(pid,comm,ip,sAddr,dAddr,port,head)
        return entry

   
    def _Hash(self,pid,comm,ip,sAddr,dAddr,port):
        key=str(pid)+str(ip)+str(comm)+sAddr+dAddr+str(port) #"costruisco" la chiave
        
        #calcolo funzione hash: string -> int
        length=len(key)
        sum=0
        for i in range(0,length):
            sum=ord(key[i])+sum
        return sum % self._size


    def _printFlows(self,head):
        while head!=None: # scorro lista di flussi
            m=head.getMTBS()
            if m != 0: # flusso contiene almeno due chiamate
                print("%-6d %-16.16s %-2d %-39s %-39s %-6d %-5d %f" % (head.getPid(), head.getComm(),
                    head.getIP(), head.getSAddr(),head.getDAddr(),
                    head.getPort(), head.getCounter(),m  
                )) #stampo flusso
            else:
                print("%-6d %-16.16s %-2d %-39s %-39s %-6d %-5d -" % (head.getPid(), head.getComm(),
                    head.getIP(), head.getSAddr(),head.getDAddr(),
                    head.getPort(), head.getCounter()
                )) #stampo flusso
            head=head.getNext()
              

    def _search(self,head,pid,comm,ip,sAddr,dAddr,port):
        while head!=None:
            if (head.getPid()==pid and head.getIP()==ip and head.getComm()==comm and 
                head.getSAddr()==sAddr and head.getDAddr()==dAddr and head.getPort()==port): # controllo se esiste già il flusso
                head.update() # aggiorno valore flusso
                return True
            else:
                head=head.getNext()
        return False