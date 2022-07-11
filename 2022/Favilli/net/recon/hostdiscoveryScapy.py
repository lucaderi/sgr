import time
import nest_asyncio
from scapy.all import Ether, ARP, sniff

def arp_scanningScapy(filePath):

    arp_scan_filter = "arp"
    arp_scan_cap = sniff(offline=filePath, filter = arp_scan_filter)
    print()

    arp_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_ip = None
    ipFound = False
    attacker_mac = None
    macFound = False
    number_of_hosts_scanned = 0
    host_scanned = {}

    for pkt in arp_scan_cap:
        if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" and pkt[ARP].op == 1:
            arp_scan_pkts +=1

            if(not first_pkt):
                first_pkt_time = pkt.time
                first_pkt = True
                attacker_mac = pkt[Ether].src
                macFound = True
                attacker_ip = pkt[ARP].psrc
                ipFound = True
            
            try: 
                host_scanned[pkt[ARP].pdst]['pkts'] = host_scanned[pkt[ARP].pdst]['pkts'] + 1
            except KeyError:
                host_scanned[pkt[ARP].pdst] = {}
                host_scanned[pkt[ARP].pdst]['pkts'] = 1
                number_of_hosts_scanned +=1
            
        last_pkt_time = pkt.time

    if(arp_scan_pkts <= 1):
        print("No Traces of 'Arp Scan' have been found.\n")
        return
    
    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_pkt_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 1
    secondThreshold = 3
    hostThreshold = 5

    if(arp_scan_pkts / number_of_hosts_scanned >= firstThreshold and 
            arp_scan_pkts / number_of_hosts_scanned <= secondThreshold 
            and number_of_hosts_scanned > hostThreshold):
        message = "Traces of 'Arp Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER macaddress: {attacker_mac}\n\tATTACKER ip address: {attacker_ip}")
    elif(arp_scan_pkt / number_of_hosts_scanned > secondThreshold and number_of_hosts_scanned > hostThreshold):
        message = "Traces of multiple 'ARP Scans' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER macaddress: {attacker_mac}\n\tATTACKER ip address: {attacker_ip}")
    else:
        print("No Traces of 'ARP Scan' have been found.")
    print()