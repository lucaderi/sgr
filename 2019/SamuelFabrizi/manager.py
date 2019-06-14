import radix
from appStruct import *
from sniffer import *
from poisoner import *
from drawer import *
from statistics import *
import config
from config import Utility


class Manager:
    """
    classe che rappresenta il gestore dell'applicazione. Instanzia e manda in esecuzione i thread
    utilizzati per sniffing (main thread), drawing e spoofing
    """

    def __init__(self, interface, ip_app_files, addresses_hosts, ip_gateway):
        """
        :param interface: interfaccia su cui catturare i pacchetti
        :param ip_app_files: lista dei files contenenti gli indirizzi ip delle varie applicazioni
        :param addresses_hosts: lista di indirizzi ip degli host da avvelenare
        :param ip_gateway: indirizzo ip del gateway
        :except ValueError: eccezione lanciata in caso di errore nell'apertura/lettura dei file
        """
        # mRtree radix tree per contenere gli indirizzi ip con cui fare matching
        self.mRtree = radix.Radix()
        self.mInterface = interface
        self.mAppList = []

        # flag utilizzato per determinare se è richiesto il poisoning (in tal caso è settato a True)
        self.mPoisonIsActive = False

        # mAppList lista delle applicazioni
        for app_path in ip_app_files:
            self.mAppList.append(AppStruct(app_path))

        if not (addresses_hosts is None):
            if ip_gateway is None:
                '''
                come specificato nell'help se si richiede lo spoofing è necessario inserire anche il
                gateway per effettuare un attacco MITM
                '''
                Utility.print_err("Devi inserire l'indirizzo ip del gateway per effettuare un attacco MITM")
            self.mPoisonIsActive = True
            self.mAddressesHosts = addresses_hosts
            self.mIpGateway = ip_gateway

        try:
            # apro e leggo gli indirizzi ip delle applicazioni salvandoli nel radix tree
            for app in self.mAppList:
                app.read_ip_app(self.mRtree)
        except ValueError as e:
            Utility.print_err(str(e))

        # statistics oggetto contenente le statistiche
        self.statistics = Statistics(self.mAppList)

        # mSniffer oggetto delegato alla cattura dei pacchetti
        self.mSniffer = Sniffer(self.mInterface, self.mRtree, self.mAppList, self.statistics)

        # mDrawer thread delegato alla rappresentazione grafica delle statistiche
        self.mDrawer = Drawer(self.statistics)

        # mPoisoner thread delegato all'avvelenamento degli ip inseriti (se richiesto)
        if self.mPoisonIsActive:
            try:
                self.mPoisoner = Poisoner(self.mAddressesHosts, self.mIpGateway, self.mInterface)
            except ValueError as e:  # lanciata nel caso in cui gli indirizzi ip forniti siano errati
                Utility.print_err(str(e))

    def run_manager(self):
        """
        rappresenta il flusso principale di esecuzione cioè il ciclo di vita del programma.
        Si preoccupa di mandare in esecuzione i vari thread per la classificazione
        del traffico relativo alle applicazioni
        """
        if self.mPoisonIsActive:
            self.mPoisoner.start()

        # avvia il thread drawer (demone)
        self.mDrawer.setDaemon(True)
        self.mDrawer.start()

        # avvia lo sniffing (main thread)
        self.mSniffer.sniff()

        if config.DEBUG:
            print("[-] End sniffing")

        if self.mPoisonIsActive:
            self.mPoisoner.stop()
            self.mPoisoner.join()

        sys.exit(0)
