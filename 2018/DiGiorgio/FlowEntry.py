# encoding=utf8
# autore: Salvatore Costantino
# modificato da: Alessandro Di Giorgio
# mail: s.costantino5@studenti.unipi.it,
#       a.digiorgio1@studenti.unipi.it

import time
class FlowEntry(object):
    """
        overview: elemento (di una lista linkata) relativo a flusso TCP connect() o TCP accept()

        attributes:
            _pid: pid processo chiamante
            _comm: nome processo chiamante
            _uid: id dell'utente che ha lanciato il processo
            _ip: versione IP
            _sAddrr: indirizzo IP sorgente
            _dAddr: indirizzo IP destinazione
            _proto4: TCP == 0, UDP == 1
            _port: porta remota o locale
            _counter: numero di TCP accept()/TCP connect()
                      o UDP rcv/snd appartenenti al flusso
            _mtbs: tempo medio trascorso tra due sys-call consecutive (del flusso)
            _lastTime: tempo dell'ultima sys-call
            _next: prossimo flusso nella lista linkata
    """

    def __init__(self, pid, uid, comm, ip, sAddr, dAddr, proto4, port, head):
        """
            costruttore oggetto
        """
        self._pid = pid
        self._uid = uid
        self._comm=comm
        self._ip = ip
        self._sAddr=sAddr
        self._dAddr=dAddr
        self._proto4=proto4
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

    def getUid(self):
        """
            restituisce uid
        """
        return self._uid

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

    def getProto4(self):
        """
            restituisce porta
        """
        return self._proto4

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
