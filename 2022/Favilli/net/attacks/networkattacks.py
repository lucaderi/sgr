import pyshark
import time
import nest_asyncio
nest_asyncio.apply()

##################### SPOOFING ##########################

def arpSpoofing(filePath):

    ArpSpoofingfilter = "arp.duplicate-address-detected or arp.duplicate-address-frame"
    arp_spoofing_cap = pyshark.FileCapture(filePath, display_filter = ArpSpoofingfilter)

    attackerMacAddr = None
    macFound = False
    arpSpoofedPkts = 0
    for pkt in arp_spoofing_cap:
        arpSpoofedPkts +=1
        if(not macFound and 'ETH' in pkt):
            attackerMacAddr = pkt.eth.addr
            macFound = True
    
    if arpSpoofedPkts > 1:
        print("\nTraces of an 'ARP Spoofing' attack have been found.\n\tPoisonus packets found: {}".format(arpSpoofedPkts)+"\n")
    else:
        print("No traces of 'Arp Spoofing' have been found.\n")


##################### DOS ##########################

'''PACKET LOSS
   unexpected packet loss combined with possible traces of dos/ddos attack is a sign that bolster a lot 
   the option of a successfully executed dos/ddos attack although alone many packet re-transmissions and
   missing packets may indicate a severe problem in the network'''
def packet_loss(filePath, total_tcp_packets):

    if total_tcp_packets == 0:
        print("No unexpected 'Packet Loss' have been found.\n")
        return -1

    pkt_loss_filter = "tcp.analysis.lost_segment or tcp.analysis.retransmission"
    packet_loss_cap = pyshark.FileCapture(filePath, display_filter = pkt_loss_filter)
    pktLossCounter = 0

    for pkt in packet_loss_cap:
        pktLossCounter += 1
    
    lossRatio = pktLossCounter / total_tcp_packets
    if(lossRatio < 1/4):
        print("No unexpected 'Packet Loss' have been found.\n")
        return 0
    else:
        message = "Unexpected 'Packets Loss' have been found."
        print(f"{message}\n\tpackets lost / re-transmitted = {pktLossCounter}\n\ttotal tcp packets = {total_tcp_packets}\n")
        if(lossRatio > 1/2):
            return 2
        else:
            return 1
        return 2

'''A correctly formed ping packet is typically 56B
   or 64B when the ICMP header is considered and 84B including 
   IPv4 header'''
def pingOfDeathIPv4(filePath):

    pingOfDeathIPv4Filter = 'icmp and not icmp.type == 3 and ip.len > 84'
    ping_of_death_IPv4_cap = pyshark.FileCapture(filePath, display_filter = pingOfDeathIPv4Filter)

    botnet = {}
    victim = None
    multipleVictims = False
    podpkts = 0
    first_ping = True
    first_ping_time = 0
    last_ping_time = 0

    for pkt in ping_of_death_IPv4_cap:
        if(first_ping):
            first_ping_time = pkt.frame_info.time_epoch
            first_ping = False
        podpkts +=1

        if('IP' in pkt):
            try: 
                botnet[pkt.ip.src]['pkts'] = botnet[pkt.ip.src]['pkts'] + 1
                botnet[pkt.ip.src]['last ping'] = float(pkt.frame_info.time_epoch)
            except KeyError:
                botnet[pkt.ip.src] = {}
                botnet[pkt.ip.src]['pkts'] = 1
                botnet[pkt.ip.src]['first ping'] = float(pkt.frame_info.time_epoch)
                botnet[pkt.ip.src]['last ping'] = float(pkt.frame_info.time_epoch)
                botnet[pkt.ip.src]['pkt length'] = int(pkt.ip.len)

            if(victim == None):
                victim = pkt.ip.dst
            elif(victim != pkt.ip.dst):
                multipleVictims = True

        last_ping_time = pkt.frame_info.time_epoch

    first_ping_time = float(first_ping_time)
    last_ping_time = float(last_ping_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_ping_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_ping_time))

    if(podpkts > 0 and len(botnet) >= 1 and multipleVictims):
        message = "Traces of a possible DoS/DDoS 'Ping of Death' attack have been found with unusual multiple attacked hosts.\nFurther investigations are highly advised.\n "
        print(f"{message}\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
        return
    elif(podpkts > 0 and len(botnet) > 1) :
        message = "Traces of DDoS 'Ping of Death' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
    elif(podpkts > 0 and len(botnet) == 1) :
        message = "Traces of DoS 'Ping of Death' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n")
    else:
        print("No Traces of DoS/DDoS 'Ping of Death' attack have been found.\n")
        return 

    for zombie, zombieInfo in botnet.items():
        print(f"\tHost : {zombie} has sent {zombieInfo['pkts']} packets of lenght: {zombieInfo['pkt length']}")
    print(f"\tVictim Host : {victim} has been reached {podpkts} times")
    print()


'''ICMP FLOOD'''
def icmpFlood(filePath):

    echoReqFilter = "icmp.type == 8 and not icmp.type == 3"
    icmp_flood_cap  = pyshark.FileCapture(filePath, display_filter = echoReqFilter)

    pingPerSec = 2
    firstThreshold = pingPerSec * 5
    secondThreshold = pingPerSec * 25

    firstEcho = True
    firstEchoTime = None
    lastEchoTime = None
    echoPktCount = 0
    botnet = {}
    victim = None
    multipleVictims = False

    for pkt in icmp_flood_cap:
        if(firstEcho):
            firstEchoTime = pkt.frame_info.time_epoch 
            firstEcho = False
        echoPktCount +=1

        if('IP' in pkt):
            try: 
                botnet[pkt.ip.src]['pkts'] = botnet[pkt.ip.src]['pkts'] + 1
                botnet[pkt.ip.src]['last ping'] = float(pkt.frame_info.time_epoch)
            except KeyError:
                botnet[pkt.ip.src] = {}
                botnet[pkt.ip.src]['pkts'] = 1
                botnet[pkt.ip.src]['first ping'] = float(pkt.frame_info.time_epoch)
                botnet[pkt.ip.src]['last ping'] = float(pkt.frame_info.time_epoch)

            if(victim == None):
                victim = pkt.ip.dst
            elif(victim != pkt.ip.dst):
                multipleVictims = True

        lastEchoTime = pkt.frame_info.time_epoch
    
    if(echoPktCount == 0):
        print("No Traces of DoS/DDoS 'ICMP Flood' attack have been found\n")
        return

    firstEchoTime = float(firstEchoTime)
    lastEchoTime = float(lastEchoTime)
    possibleHostAtkCount = 0
    hostAtkCount = 0

    try:
        for zombie, zombieInfo in botnet.items():
            if int(zombieInfo['pkts']) / float(zombieInfo['last ping'] - zombieInfo['first ping']) > secondThreshold:
                hostAtkCount += 1
            elif int(zombieInfo['pkts']) / float(zombieInfo['last ping'] - zombieInfo['first ping']) > firstThreshold:
                possibleHostAtkCount += 1
    except ZeroDivisionError:
        del botnet[zombie] #if the hosts in the botnet are not flagged as possible attacker nor attacker remove them from the botnet

    if len(botnet) == 0: # all the hosts were legit
        print("No Traces of DoS/DDoS 'ICMP Flood' attack have been found\n")
        return

    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(firstEchoTime))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lastEchoTime))

    if(hostAtkCount >= 1 or possibleHostAtkCount >= 1) and multipleVictims:
        message = "Traces of a possible 'ICMP Ping' Scan have been found, further investigations are needed.\n"
        print(message)
        return
    elif(hostAtkCount > 1) :
        message = "Traces of DDoS 'ICMP Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {hostAtkCount}\n")
    elif(hostAtkCount == 1) :
        message = "Traces of DoS 'ICMP Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n")
    else:
        print("No Traces of DoS/DDoS 'ICMP Flood' attack have been found.\n")
        return    
    
    for zombie, zombieInfo in botnet.items():
        if (int)(zombieInfo['pkts'] / (float)(zombieInfo['last ping'] - zombieInfo['first ping']) > secondThreshold):
            print(f"\tHost : {zombie} has sent {zombieInfo['pkts']} packets in {zombieInfo['last ping'] - zombieInfo['first ping']} seconds")
        if(possibleHostAtkCount != 0):
            print(f"\n\t{possibleHostAtkCount} hosts could have made an attempt to make an 'ICMP flood'\n")
            for zombie, zombieInfo in botnet.items():
                if ((int)(zombieInfo['pkts'] / (float)(zombieInfo['last ping'] - zombieInfo['first ping']) < secondThreshold)
                    and (int)(zombieInfo['pkts']) / float (zombieInfo['last ping'] - zombieInfo['first ping']) > firstThreshold):
                    print(f"\tHost : {zombie} has sent {zombieInfo['pkts']} packets in {zombieInfo['last ping'] - zombieInfo['first ping']} seconds")
    print(f"\tVictim Host:{victim} has been reached {echoPktCount} times")
    print()


'''TCP SYN FLOOD attack'''
def syn_flood(filePath):

    syn_flood_filter = "tcp.flags.syn == 1 and tcp.flags.ack == 0"
    syn_ack_filter = "tcp.flags.syn == 1 and tcp.flags.ack == 1"

    syn_flood_cap = pyshark.FileCapture(filePath, display_filter = syn_flood_filter)
    syn_ack_cap = pyshark.FileCapture(filePath, display_filter = syn_ack_filter)

    synAck_pkts = 0
    synNotAck_pkts = 0
    firstSyn = True
    firstSynTime = None
    lastSynTime = None
    botnet = {}
    victim = None
    multipleVictims = False

    for pkt in syn_flood_cap:
        if(firstSyn):
            firstSynTime = pkt.frame_info.time_epoch 
            firstSyn = False
        synNotAck_pkts += 1

        if('IP' in pkt):
            try: 
                botnet[pkt.ip.src]['pkts'] = botnet[pkt.ip.src]['pkts'] + 1
                botnet[pkt.ip.src]['last syn'] = float(pkt.frame_info.time_epoch)
            except KeyError:
                botnet[pkt.ip.src] = {}
                botnet[pkt.ip.src]['pkts'] = 1
                botnet[pkt.ip.src]['first syn'] = float(pkt.frame_info.time_epoch)
                botnet[pkt.ip.src]['last syn'] = float(pkt.frame_info.time_epoch)

            if(victim == None):
                victim = pkt.ip.dst
            elif(victim != pkt.ip.dst):
                multipleVictims = True
    
        lastSynTime = pkt.frame_info.time_epoch

    if(synNotAck_pkts <= 1):
        print("No Traces of DoS/DDoS 'Syn Flood' attack have been found\n")
        return

    for pkt in syn_ack_cap:
        synAck_pkts +=1

    try:
        synAckRatio = synAck_pkts/synNotAck_pkts 
    except ZeroDivisionError:
        synAckRatio = 1

    firstSynTime = float(firstSynTime)
    lastSynTime = float(lastSynTime)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(firstSynTime))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lastSynTime))

    if(multipleVictims and synNotAck_pkts > 10):
        message = "Traces of a possible 'TCP Syn' Scan have been found, further investigations are needed.\n"
        print(message)
        return
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
    elif(synAckRatio > 1/3 and synAckRatio < 1 and len(botnet) > 1) :
        message = "Traces of a possible DDoS 'Syn Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
    elif(synAckRatio > 1/3 and synAckRatio < 1 and len(botnet) == 1) :
        message = "Traces of a possible DoS 'Syn Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}")
    elif(synAckRatio < 1/3 and len(botnet) > 1) :
        message = "Traces of a DDoS 'Syn Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
    elif(synAckRatio < 1/3 and len(botnet) == 1) :
        message = "Traces of a DoS 'Syn Flood' attack have been found"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}")
    else:
        print("No Traces of DoS/DDoS 'Syn Flood' attack have been found\n")
        return

    for zombie, zombieInfo in botnet.items():
            print(f"\tHost : {zombie} has sent {zombieInfo['pkts']} packets in {zombieInfo['last syn'] - zombieInfo['first syn']} seconds")
    print(f"\tVictim Host: \t{victim} has been reached {synNotAck_pkts} times")
    print()

'''DNS Request flood, attacker general requests use the UDP protocol with a DESTination port of 53 
   to make a dns request to a domain'''
def dns_req_flood(filePath, totalPackets):

    dns_req_flood_filter = "udp and udp.dstport == 53 and dns"
    dns_req_cap = pyshark.FileCapture(filePath, display_filter = dns_req_flood_filter)

    botnet = {}
    victim = None
    multipleVictims = False
    dnsReqPkts = 0
    first_req = True
    first_req_time = 0
    last_req_time = 0

    for pkt in dns_req_cap:
        if(first_req):
            first_req_time = pkt.frame_info.time_epoch 
            first_req = False

        dnsReqPkts += 1

        if('IP' in pkt):
            try:
                botnet[pkt.ip.src]['pkts'] = botnet[pkt.ip.src]['pkts'] + 1
                botnet[pkt.ip.src]['last req'] = float(pkt.frame_info.time_epoch)
            except KeyError:
                botnet[pkt.ip.src] = {}
                botnet[pkt.ip.src]['pkts'] = 1
                botnet[pkt.ip.src]['first req'] = float(pkt.frame_info.time_epoch)
                botnet[pkt.ip.src]['last req'] = float(pkt.frame_info.time_epoch)
            
            if(victim == None):
                victim = pkt.ip.dst
            elif(victim != pkt.ip.dst):
                multipleVictims = True

        last_req_time = pkt.frame_info.time_epoch

    first_req_time = float(first_req_time)
    last_req_time = float(last_req_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_req_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_req_time))
      
    if(last_req_time - first_req_time == 0):
        print("No traces of 'DNS Request Flood' attack have been found\n")
        return
    elif(multipleVictims and dnsReqPkts / (last_req_time - first_req_time) > 1 and dnsReqPkts/totalPackets > 1/15):
        message = "Traces of a possible DoS/DDoS 'DNS Request Flood' attack have been found with unusual multiple attacked hosts.\n Further investigations are highly advised.\n"
        print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
        return
    elif(dnsReqPkts/ (last_req_time - first_req_time) > 1 and dnsReqPkts /totalPackets > 1/9):
        if len(botnet) > 1:
            message = "Traces of a DDoS 'DNS Request Flood' attack have been found"
            print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
        else:
            message = "Traces of a DOS 'DNS Request Flood' attack have been found"
            print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n")
    elif(dnsReqPkts / (last_req_time - first_req_time) > 1 and dnsReqPkts/totalPackets > 1/15):
        if len(botnet) > 1:
            message = "Traces of a possible DDoS 'DNS Request Flood' attack have been found,further investigation is needed"
            print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}\n\tBOTNET cardinality = {len(botnet)}\n")
        else:
            message = "Traces of a possible 'DNS Request Flood' DOS attack have been found, further investigation is needed"
            print(f"{message}:\n\tattack STARTED: {startTime}\n\tattack ENDED: {endTime}")
    else:
        print("No traces of 'DNS Request Flood' attack have been found\n")
        return

    for zombie, zombieInfo in botnet.items():
        print(f"\tHost: \t{zombie} has sent {zombieInfo['pkts']} packets in {zombieInfo['last req'] - zombieInfo['first req']} seconds")
    print(f"\tVictim Host: \t{victim} has been reached {dnsReqPkts} times")
    print()    
    
##################### VLAN/CISCO ##########################

'''Check if there are any DTP (dynamic Trunking Protocol) or packets tagged with 
   multiple Vlan tags'''
def vlan_hopping(filePath):

    vlan_hop_filter = "dtp or vlan.too_many_tags"   
    vlan_hopping_cap = pyshark.FileCapture(filePath, display_filter = vlan_hop_filter)
    pktHopCount = 0
    
    for pkt in vlan_hopping_cap:
        pktHopCount += 1
    if(pktHopCount > 1):
        print("Traces of a possible 'Vlan Hopping' attack have been found:\n\tPoisonus packets = {}".format(pktHopCount))
    else:
        print("No traces of 'Vlan Hopping' exploitation have been found.")
    print()