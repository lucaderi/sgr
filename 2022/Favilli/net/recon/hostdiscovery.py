import pyshark
import time
import nest_asyncio
nest_asyncio.apply()


def arp_scanning(filePath):

    arp_scan_filter = "arp.opcode == 1 and arp.dst.hw_mac==00:00:00:00:00:00"
    arp_scan_cap = pyshark.FileCapture(filePath, display_filter = arp_scan_filter)

    arp_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_mac = None
    macFound = False

    for pkt in arp_scan_cap:

        arp_scan_pkts +=1

        if(not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True
            attacker_mac = pkt.eth.src
            macFound = True
            
        last_pkt_time = pkt.frame_info.time_epoch

    if(arp_scan_pkts <= 1):
        print("No Traces of 'Arp Scan' have been found.\n")
        return
    
    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_pkt_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 20
    secondThreshold = 50

    if(arp_scan_pkts > secondThreshold):
        message = "Traces of 'Arp Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER macaddress: {attacker_mac}")
    elif(arp_scan_pkts > firstThreshold):
        message = "Traces of a possible 'ARP Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    else:
        print("No Traces of 'ARP Scan' have been found.")
    print()


def IP_protocol_scan(filePath):
    ip_proto_filter = "icmp.type == 3 and icmp.code == 2"
    ip_proto_scan_cap = pyshark.FileCapture(filePath, display_filter = ip_proto_filter)

    ip_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_IP = None
    IP_found = False

    for pkt in ip_proto_scan_cap:
        ip_scan_pkts += 1

        if (not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True
            attacker_IP = pkt.ip.src
            IP_found = True
        last_ping_time = pkt.frame_info.time_epoch

    if(ip_scan_pkts <= 1):
        print("No Traces of 'IP Protocol Scan' have been found.\n")
        return

    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_ping_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 20
    secondThreshold = 70

    if(ip_scan_pkts /(last_pkt_time - first_pkt_time) > secondThreshold):
        message = "Traces of an 'IP Protocol Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(ip_scan_pkts /(last_pkt_time - first_pkt_time) > firstThreshold):
        message = "Traces of a possible 'IP Protocol Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    else:
        print("No Traces of 'IP Protocol Scan' have been found.")
    print()


def icmp_ping_sweeps_scan(filePath):

    icmp_ping_sweeps_filter = "icmp.type == 8 and not icmp.type == 3"
    icmp_ping_sweeps_scan_cap = pyshark.FileCapture(filePath, display_filter = icmp_ping_sweeps_filter)

    icmp_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_IP = None
    IP_found = False
    number_of_hosts_scanned = 0
    host_scanned = {}

    for pkt in icmp_ping_sweeps_scan_cap:
        icmp_scan_pkts += 1

        if (not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True

        if('IP' in pkt):
            try: 
                host_scanned[pkt.ip.dst]['pkts'] = host_scanned[pkt.ip.dst]['pkts'] + 1
            except KeyError:
                host_scanned[pkt.ip.dst] = {}
                host_scanned[pkt.ip.dst]['pkts'] = 1
                number_of_hosts_scanned +=1
            if(not IP_found):
                attacker_IP = pkt.ip.src
                IP_found = True
        last_ping_time = pkt.frame_info.time_epoch
        
    if(icmp_scan_pkts <= 1):
        print("No Traces of 'ICMP Scan' have been found.\n")
        return

    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_ping_time)
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 1
    secondThreshold = 3
    hostThreshold = 5
    dosThreshold = 10

    if(icmp_scan_pkts / number_of_hosts_scanned >= firstThreshold and 
            icmp_scan_pkts / number_of_hosts_scanned <= secondThreshold 
            and number_of_hosts_scanned > hostThreshold):
        message = "Traces of an 'ICMP Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(icmp_scan_pkts / number_of_hosts_scanned > secondThreshold and number_of_hosts_scanned > hostThreshold):
        message = "Traces of multiple 'ICMP Scans' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(number_of_hosts_scanned == 1 and (icmp_scan_pkts / (last_pkt_time - first_pkt_time)) >= dosThreshold):
        message = "Traces of a possible 'ICMP DoS/DDoS' attack have been found, but further investigation is required."
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tPACKETS PER SECOND : {icmp_scan_pkts / (last_pkt_time - first_pkt_time)}")
    else:
        print("No Traces of 'ICMP Scan' have been found.")
    print()


def tcp_syn_ping_sweep(filePath):
    tcp_syn_ping_sweeps_filter = "tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.dstport == 80"
    tcp_syn_ping_sweeps_scan_cap = pyshark.FileCapture(filePath, display_filter = tcp_syn_ping_sweeps_filter)

    tcp_syn_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_IP = None
    IP_found = False
    number_of_hosts_scanned = 0
    host_scanned = {}

    for pkt in tcp_syn_ping_sweeps_scan_cap:
        tcp_syn_scan_pkts += 1

        if (not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True

        if('IP' in pkt):
            try: 
                host_scanned[pkt.ip.dst]['pkts'] = host_scanned[pkt.ip.dst]['pkts'] + 1
            except KeyError:
                host_scanned[pkt.ip.dst] = {}
                host_scanned[pkt.ip.dst]['pkts'] = 1
                number_of_hosts_scanned +=1
            if(not IP_found):
                attacker_IP = pkt.ip.src
                IP_found = True
        last_ping_time = pkt.frame_info.time_epoch
        
        
    if(tcp_syn_scan_pkts <= 1):
        print("No Traces of 'TCP Syn Ping Scan' have been found.\n")
        return
    
    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_ping_time)
    
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 1
    secondThreshold = 3
    hostThreshold = 5
    dosThreshold = 5

    if(tcp_syn_scan_pkts / number_of_hosts_scanned >= firstThreshold and 
            tcp_syn_scan_pkts / number_of_hosts_scanned <= secondThreshold 
            and number_of_hosts_scanned > hostThreshold):
        message = "Traces of an 'TCP Syn Ping Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(tcp_syn_scan_pkts / number_of_hosts_scanned > secondThreshold and number_of_hosts_scanned > hostThreshold):
        message = "Traces of multiple 'TCP Syn Ping Scans' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(number_of_hosts_scanned == 1 and tcp_syn_scan_pkts / (last_pkt_time - first_pkt_time) >= dosThreshold):
        message = "Traces of a possible 'TCP Syn DoS/DDoS' attack have been found, but further investigation is required."
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tPACKETS PER SECOND : {tcp_syn_scan_pkts / (last_pkt_time - first_pkt_time)}")
    else:
        print("No Traces of 'TCP Syn Ping Scan' have been found.")
    print()


def tcp_ack_ping_sweep(filePath):
    tcp_ack_ping_sweeps_filter = "tcp.flags.syn == 0 and tcp.flags.ack == 1 and tcp.len == 0"
    tcp_ack_ping_sweeps_scan_cap = pyshark.FileCapture(filePath, display_filter = tcp_ack_ping_sweeps_filter)

    tcp_ack_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_IP = None
    IP_found = False
    number_of_hosts_scanned = 0
    host_scanned = {}

    for pkt in tcp_ack_ping_sweeps_scan_cap:
        tcp_ack_scan_pkts += 1

        if (not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True

        if('IP' in pkt):
            try: 
                host_scanned[pkt.ip.dst]['pkts'] = host_scanned[pkt.ip.dst]['pkts'] + 1
            except KeyError:
                host_scanned[pkt.ip.dst] = {}
                host_scanned[pkt.ip.dst]['pkts'] = 1
                number_of_hosts_scanned +=1
            if(not IP_found):
                attacker_IP = pkt.ip.src
                IP_found = True
        last_ping_time = pkt.frame_info.time_epoch
        
        
    if(tcp_ack_scan_pkts <= 1):
        print("No Traces of 'TCP Ack Ping Scan' have been found.\n")
        return
    
    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_ping_time)
    
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 1
    secondThreshold = 3
    hostThreshold = 5

    if(tcp_ack_scan_pkts / number_of_hosts_scanned >= firstThreshold and 
            tcp_ack_scan_pkts / number_of_hosts_scanned <= secondThreshold 
            and number_of_hosts_scanned > hostThreshold):
        message = "Traces of a 'TCP Ack Ping Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(tcp_ack_scan_pkts / number_of_hosts_scanned > secondThreshold and number_of_hosts_scanned > hostThreshold):
        message = "Traces of multiple 'TCP Ack Ping Scans' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    else:
        print("No Traces of 'TCP Ack ping scan' have been found.")
    print()

def udp_ping_scan(filePath):
    udp_ping_sweeps_filter = "udp.dstport == 40125 and udp.length == 8"
    udp_ping_sweeps_scan_cap = pyshark.FileCapture(filePath, display_filter = udp_ping_sweeps_filter)

    udp_scan_pkts = 0
    first_pkt_time = 0
    first_pkt = False
    last_pkt_time = 0
    attacker_IP = None
    IP_found = False
    number_of_hosts_scanned = 0
    host_scanned = {}

    for pkt in udp_ping_sweeps_scan_cap:
        udp_scan_pkts += 1

        if (not first_pkt):
            first_pkt_time = pkt.frame_info.time_epoch
            first_pkt = True

        if('IP' in pkt):
            try: 
                host_scanned[pkt.ip.dst]['pkts'] = host_scanned[pkt.ip.dst]['pkts'] + 1
            except KeyError:
                host_scanned[pkt.ip.dst] = {}
                host_scanned[pkt.ip.dst]['pkts'] = 1
                number_of_hosts_scanned +=1
            if(not IP_found):
                attacker_IP = pkt.ip.src
                IP_found = True
        last_ping_time = pkt.frame_info.time_epoch
        
        
    if(udp_scan_pkts <= 1):
        print("No Traces of 'UDP Ping Scan' have been found.\n")
        return
    
    first_pkt_time = float(first_pkt_time)
    last_pkt_time = float(last_ping_time)
    
    startTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_pkt_time))
    endTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pkt_time))

    firstThreshold = 1
    secondThreshold = 3
    hostThreshold = 5

    if(udp_scan_pkts / number_of_hosts_scanned >= firstThreshold and 
            udp_scan_pkts / number_of_hosts_scanned <= secondThreshold 
            and number_of_hosts_scanned > hostThreshold):
        message = "Traces of an 'UDP Ping Scan' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    elif(udp_scan_pkts / number_of_hosts_scanned > secondThreshold and number_of_hosts_scanned > hostThreshold):
        message = "Traces of multiple 'UDP Ping Scans' have been found"
        print(f"{message}:\n\tScan STARTED: {startTime}\n\tScan ENDED: {endTime}\n\tATTACKER : {attacker_IP}")
    else:
        print("No Traces of 'UDP Ping Scan' have been found.")
    print()
