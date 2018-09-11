# encoding=utf8
# autore: Salvatore Costantino
# modificato da: Alessandro Di Giorgio
# mail: s.costantino5@studenti.unipi.it,
#       a.digiorgio1@studenti.unipi.it

from FlowEntry import *
from AbstractFlowTable import *
import pwd
import DockerManager

class SimpleFlowTable(AbstractFlowTable):
    """
        overview:   HashTable di flussi relativi a chiamate TCP connect()/TCP accept()/UDP rcv()/UDP send()
                    chiave composta dai seguenti attrributi:
                        1)pid: PID del processo chiamante
                        2)uid: id dell'utente che ha lanciato il processo
                        3)comm: nome processo chiamante
                        4)ip: versione IP
                        5)sAddr: indirizzo IP sorgente
                        6)dAddr: indirizzo IP destinazione
                        7)port: porta remota / porta locale
                        8)proto4: protocollo L4 (TCP/UDP)

        attributes: (ereditati dalla classe base, AbstractFlowTable)
    """

    def _linkNewEntry(self,pid,uid,comm,ip,sAddr,dAddr,proto4,port,head):
        # le informazioni sui container le prelevo solo se il flusso è nuovo.
        # Negli altri casi è inutile (per uno stesso PID sarà sempre uguale)

        if DockerManager.enabled:
            cntr = DockerManager.getContainerByPid(pid)
            if cntr is not None:
                comm = comm + " @ " + cntr.attrs['Name'][1:]

        entry=FlowEntry(pid,uid,comm,ip,sAddr,dAddr,proto4,port,head)
        return entry


    def _Hash(self,pid,uid,comm,ip,sAddr,dAddr,proto4,port):
        key=str(pid)+str(ip)+sAddr+dAddr+str(proto4)+str(port) #"costruisco" la chiave

        #calcolo funzione hash: string -> int
        length=len(key)
        sum=0
        for i in range(0,length):
            sum=ord(key[i])+sum
        return sum % self._size


    def _printFlows(self,head):
        while head!=None: # scorro lista di flussi
            m=head.getMTBS()

            # ricava il nome utente dal uid
            try:
                user = pwd.getpwuid(head.getUid()).pw_name;
            except Exception as e:
                user = ""

            if m != 0: # flusso contiene almeno due chiamate
                print("%-6d %-26.26s %-10.10s %-2d %-5s %-30s %-30s %-6d %-5d %f" %
                   (head.getPid(), head.getComm(), user,
                    head.getIP(), "TCP" if head.getProto4() == 0 else "UDP",
                    head.getSAddr(), head.getDAddr(),
                    head.getPort(), head.getCounter(),m
                )) #stampo flusso
            else:
                print("%-6d %-26.26s %-10.10s %-2d %-5s %-30s %-30s %-6d %-5d -" %
                   (head.getPid(), head.getComm(), user,
                    head.getIP(), "TCP" if head.getProto4() == 0 else "UDP",
                    head.getSAddr(), head.getDAddr(),
                    head.getPort(), head.getCounter()
                )) #stampo flusso
            head=head.getNext()


    def _search(self,head,pid,uid,comm,ip,sAddr,dAddr,proto4,port):
        while head!=None:
            if (head.getPid()==pid and head.getIP()==ip and
                head.getSAddr()==sAddr and head.getDAddr()==dAddr and
                head.getProto4()==proto4 and head.getPort()==port): # controllo se esiste già il flusso
                head.update() # aggiorno valore flusso
                return True
            else:
                head=head.getNext()
        return False
