# encoding=utf8 
# autore: Salvatore Costantino
# mail: s.costantino5@studenti.unipi.it

class AbstractFlowTable(object):
    
    """
    overview: HashTable di flussi con chiave composta da 6 attributi
    
    attributes:
        (protected) _size: dimensione tabella hash (numero buckets)
        (protected) _buckets: array di liste (di trabocco)
    """
    
    _min_size=20 # dimensione di default tabella hash

    def __init__(self,size=None):
        """ 
            Costruttore oggetto
        """
        self._size=size if (size !=None and size > 0) else AbstractFlowTable._min_size #dimensione iniziale tabella hash
        self._buckets= [None] * self._size #creo array di liste


    def insert(self,attr1,attr2,attr3,attr4,attr5,attr6):
        """ 
            consente di inserire nella tabella un nuovo flusso (oppure aggiornarlo se già esiste)  
        """
        idx=self._Hash(attr1,attr2,attr3,attr4,attr5,attr6) #calcolo funzione hash
        if not self._search(self._buckets[idx],attr1,attr2,attr3,attr4,attr5,attr6): #se nuovo flusso
            self._buckets[idx]=self._linkNewEntry(attr1,attr2,attr3,attr4,attr5,attr6,self._buckets[idx]) #inserisco flusso

    def readTable(self):
        """ 
            scansiona tutti i buckets della tabella hash e ne stampa i flussi
        """
        for head in self._buckets:
            self._printFlows(head)
    
    def _linkNewEntry(self,attr1,attr2,attr3,attr4,attr5,attr6,head): #abstract
        """ 
            responsabile della creazione e dell'inserimento di un nuovo flusso
            restituisce la testa della lista
            (implementata da classi concrete)
        """
        raise NotImplementedError
   
    def _Hash(self,attr1,attr2,attr3,attr4,attr5,attr6): #abstract
        """ 
            funzione hash
            restituisce l'indice di una cella
            (implementatata da classi concrete)
        """
        raise NotImplementedError

    def _printFlows(self,head): #abstract
        """ 
            stampa flussi contenuti nella lista head
            (implementatata da classi concrete)
        """
        raise NotImplementedError

    def _search(self,head,attr1,attr2,attr3,attr4,attr5,attr6): #abstract
        """ 
            ricerca flusso
            se lo trova, ne aggiorna il valore e restituisce true
            altrimenti restituisce false
        """
        raise NotImplementedError
        
