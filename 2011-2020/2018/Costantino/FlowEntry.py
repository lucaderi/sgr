# encoding=utf8
# autore: Salvatore Costantino
# mail: s.costantino5@studenti.unipi.it 

import time
class FlowEntry(object):
    """
        overview: elemento (di una lista linkata) relativo a flusso TCP connect() o TCP accept()

        attributes:
            _pid: pid processo chiamante
            _comm: nome processo chiamante
            _ip: versione IP
            _sAddrr: indirizzo IP sorgente
            _dAddr: indirizzo IP destinazione
            _port: porta remota (se TCP connect())/locale (se TCP accept())
            _counter: numero di TCP accept()/TCP connect() appartenenti al flusso
            _mtbs: tempo medio trascorso tra due sys-call consecutive (del flusso)
            _lastTime: tempo dell'ultima sys-call
            _next: prossimo flusso nella lista linkata
    """

    def __init__(self, pid, comm, ip, sAddr, dAddr,port,head):
        """
            costruttore oggetto
        """
        self._pid = pid
        self._comm=comm
        self._ip = ip
        self._sAddr=sAddr
        self._dAddr=dAddr
        self._port=port
        self._counter=1
        self._mtbs=0
        self._lastTime = time.time()
        self._next = head


    def getPid(self):
        """
            restituisce pid
        """
        return self._pid

    def getComm(self):
        """
            restituisce nome processo
        """
        return self._comm

    def getIP(self):
        """
            restituisce versione IP
        """
        return self._ip
    
    def getSAddr(self):
        """
            restituisce IP sorgente
        """
        return self._sAddr
    
    def getDAddr(self):
        """
            restituisce IP destinatario
        """
        return self._dAddr
    
    def getPort(self):
        """
            restituisce porta
        """
        return self._port
    
    def getCounter(self):
        """
            restituisce numero chiamate appartenenti al flusso
        """
        return self._counter
    
    def update(self):
        """
            aggiornamento flusso
        """
        self._updateMTBS()
        self._incCounter()

    def _incCounter(self):
        """
            incrementa contatore flusso
        """
        self._counter=self._counter+1
    
    def _updateMTBS(self):
        """
            aggiorna tempo medio tra due sys-call consecutive (appartenenti al flusso)
        """
        now=time.time() #timestamp attuale
        diff=now-self._lastTime #tempo passato dall'ultima sys-call appartenente al flusso
        self._lastTime=now #aggiorno tempo
        self._mtbs=(self._mtbs+diff)/(self._counter) #aggiorno tempo medio

    def getMTBS(self):
        """
            ritorna tempo medio tra due sys-call consecutive
        """
        return self._mtbs

    def getNext(self):
        """
            restituisce maniglia al prossimo flusso
        """
        return self._next