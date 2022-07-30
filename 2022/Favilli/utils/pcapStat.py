import pyshark

def basicStat(cap):

    packets = 0
    tcpPackets = 0 
    udpPackets = 0 
    icmpPackets = 0
    arpPackets = 0
    dnsPackets = 0
    snmpPackets = 0
    ftpPackets = 0
    smtpPackets = 0
    dtpPackets = 0
    uncategorized = 0 

    for pkt in cap:
        packets += 1
        if('TCP' in pkt):
            tcpPackets +=1
        elif('UDP' in pkt):
            udpPackets +=1
        elif('ICMP' in pkt):
            icmpPackets +=1
        elif('ARP' in  pkt):
            arpPackets +=1
        elif('DNS' in pkt):
            dnsPackets +=1
        elif('SMTP' in pkt):
            smtpPackets +=1
        elif('FTP' in pkt):
            ftpPackets += 1
        elif('SNMP' in pkt):
            snmpPackets +=1
        elif('DPT' in pkt):
            dtpPackets +=1
        else:
            uncategorized +=1
            
    stats = {
        "total_packets": packets,
        "tcp_packets" : tcpPackets,
        "udp_packets" : udpPackets,
        "icmp_packets" : icmpPackets, 
        "arp_packets" : arpPackets,
        "dns_packets" : dnsPackets,
        "snmp_packets" : snmpPackets,
        "ftp_packets" : ftpPackets,
        "smtp_packets" : smtpPackets,
        "dtp_packets" : dtpPackets,
        "uncategorized" : uncategorized,
    }

    return stats