import sys
import os
import pyshark 
import nest_asyncio
nest_asyncio.apply()

from net.attacks.networkattacks import *
from net.recon.hostdiscovery import *

if len(sys.argv) > 1 and sys.argv[1] == '-s':
    from net.recon.hostdiscoveryScapy import arp_scanningScapy
from utils.parser import *
from utils.pcapStat import *
import utils.menu


####################### CALL ATTACKS ###########################


def callAttacks(attackTOAnalyse, filePath, stats, flag):

    attacks = [arpSpoofing, packet_loss, pingOfDeathIPv4, icmpFlood, 
                syn_flood, dns_req_flood, vlan_hopping]
    if(flag):
        scans = [arp_scanningScapy, IP_protocol_scan, icmp_ping_sweeps_scan, 
                tcp_syn_ping_sweep, tcp_ack_ping_sweep, udp_ping_scan]
    else:
        scans = [arp_scanning, IP_protocol_scan, icmp_ping_sweeps_scan, 
                tcp_syn_ping_sweep, tcp_ack_ping_sweep, udp_ping_scan]

    if(attackTOanalyse[0] == 1):
        if(attackTOanalyse[1] == 1): #Spoof
            if(attackTOanalyse[2] == 1):
                attacks[0](filePath)
        elif(attackTOanalyse[1] == 2): #DDoS
            if(attackTOanalyse[2] == 1):
                attacks[1](filePath, stats['tcp_packets'])
            elif(attackTOanalyse[2] == 5):
                attacks[5](filePath, stats['total_packets'])
            elif(attackTOanalyse[2] == 6):
                allAttacks(attacks[1:6], filePath, stats)
            else:
                attacks[attackTOanalyse[2]](filePath)
        elif(attackTOanalyse[1] == 3): # Vlan
            if(attackTOanalyse[2] == 1):
                attacks[-1](filePath)
        elif(attackTOanalyse[1] == 4): # All attacks
            allAttacks(attacks, filePath, stats)
    elif(attackTOanalyse[0] == 2):
        if(attackTOanalyse[1] == 1):
            if attackTOanalyse[2] !=  7:
                scans[attackTOanalyse[2]](filePath)
            else:
                allScans(scans, filePath)
            
    elif(attackTOanalyse[0] == 3):
        print("RECON: \n")
        allScans(scans, filePath)
        print("\nNETWORK ATTACKS: \n")
        allAttacks(attacks, filePath, stats)
    else:
        print("Some error has accurred, quitting...")
        sys.exit(-1)
        

def allAttacks(attacks, filePath, stats):
    for a in attacks:
            if a == packet_loss:
                a(filePath, stats['tcp_packets'])
            elif a == dns_req_flood:
                a(filePath, stats['total_packets'])
            else:
                a(filePath)

def allScans(scans, filePath):
     for s in scans:
            s(filePath)
            
####################### MAIN ########################

if __name__ == "__main__":

    scapee = False
    #pcap path
    if len(sys.argv) == 3 and os.path.isfile(sys.argv[2]):
        filePath = sys.argv[2]
        if(sys.argv[1] == '-s'):
            scapee = True
    elif len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        filePath = sys.argv[1]
    elif len(sys.argv) == 2 and sys.argv[1] == '-s':
            scapee = True
            filePath = inputFilePath()
    else:
        filePath = inputFilePath()
    
    attackTOanalyse = utils.menu.menu()
    print("\nANALYSING the pcap...\n")
    
    cap = pyshark.FileCapture(filePath)
    stats = basicStat(cap)
    callAttacks(attackTOanalyse, filePath, stats, scapee)
    

    #STATS 
    print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\nGeneral stats:")
    for key, value in stats.items():
        if(key == 'total_packets'):
            print(f"\t{key} : {value}")
        elif(value != 0):
            print(f"\t{key} : {value}\t({value*100/stats['total_packets']}%)")
    print()

