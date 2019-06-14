import sys

'''
costanti per la configurazione dell'applicazione
'''

DEBUG = False  # flag per effettuare il debug
WAIT_TIME_POISON = 1  # numero di secondi di wait per il thread che effettua l'arp poisoning
TIME_REFRESH_GRAPH = 2000  # numero di millisecondi per l'aggiornamento del grafico
DIR_FILES_APP = "./dir_files_app/"  # path della directory contenente i file con gli i range di indirizzi ip delle applicazioni

'''
stringhe contenenti la descrizione dei vari argomenti per l'help del programma
'''
DESCR_INTERFACE = 'l\'interfaccia su cui catturare i pacchetti'
DESCR_FILES = 'lista di file contenenti un insieme di indirizzi ip per una certa applicazione'
DESCR_ADDRESSES_HOST ='lista di indirizzi ip degli host su cui effettuare un attacco MITM'
DESCR_GATEWAY = 'indirizzo ip del gateway (obbligatorio se si vuole effettuare un attacco MITM)'


class Utility:

    @staticmethod
    def print_err(err):
        """
        stampa la descrizione dell'errore e comporta la terminazione brutale del programma

        :param err: stringa che descrive l'errore

        .. note:: invocata solo in caso di errori irrecuperabili
        """
        print("\n[-] ERROR: ", err, file=sys.stderr)
        sys.exit(-1)

