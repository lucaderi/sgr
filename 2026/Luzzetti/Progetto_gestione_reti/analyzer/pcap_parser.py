from scapy.all import rdpcap

def read_packets(pcap_path):
    """
    Legge tutti i pacchetti contenuti in un file PCAP.
    
    La cattura viene eseguita esternamente tramite Wireshark o tcpdump.
    Il progetto si concentra sull'analisi offline del traffico.
    """
    packets = rdpcap(str(pcap_path))
    return list(packets)
