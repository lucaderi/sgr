import pyshark
import asyncio
import config
from config import Utility


class Sniffer:
    """
    classe che rappresenta lo sniffer
    """

    def __init__(self, interface, rtree, list_app, statistics):
        """
        :param interface: interfaccia su cui catturare i pacchetti
        :param rtree: radix tree per la memorizzazione del range di indirizzi ip delle varie applicazioni
        :param list_app: lista di applicazioni
        :param statistics: oggetto che rappresenta le statistiche ottenute dal programma
        """
        self.mInterface = interface
        self.mRtree = rtree
        self.apps = list_app
        self.statistics = statistics

    def compute_statistics(self, pkt):
        """
        :param pkt: pacchetto catturato
        """
        try:
            # cerco un matching nel radix tree
            rnode = self.mRtree.search_best(pkt.ip.src)
            if not (rnode is None):
                # salvo il nome dell'applicazione e il numero di bytes trovato nell'header ip
                appname = rnode.data["app"]
                n_bytes = int(pkt.ip.len)
                if config.DEBUG:
                    print("[+] ", appname, " # ", n_bytes, end='\n')
                # aggiorno le statistiche
                self.statistics.update(appname, n_bytes)
        except AttributeError:
            # ignoro l'errore perché considero solo pacchetti con header ip
            pass

    def sniff(self):
        """
        effettua il vero e proprio sniffing

        :except KeyboardInterrupt: interruzione da tastiera
        :except asyncio.TimeoutError: interruzione per eventuali errori nel ciclo principale della LiveCapture
        :except RuntimeError: errore a Runtime nella cattura di pacchetti

        .. note:: l'unica interruzione che permette una terminazione gentile è la KeyboardInterrupt
        """
        cap = pyshark.LiveCapture(interface=self.mInterface)
        try:
            cap.apply_on_packets(self.compute_statistics, timeout=None)
        except KeyboardInterrupt:
            print("\nExit...")
            return
        except asyncio.TimeoutError as e:
            Utility.print_err(str(e))
        except RuntimeError as e:
            Utility.print_err(str(e))
