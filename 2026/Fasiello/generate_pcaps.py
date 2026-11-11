#!/usr/env/python3
import os
from scapy.all import Ether, IP, TCP, UDP, wrpcap

def generate_normal_pcap(filename):
    print(f"Generating normal traffic PCAP: {filename}...")
    packets = []
    base_time = 1790082000.0
    local_ip = "192.168.1.100"
    remote_ip = "93.184.216.34"

    for i in range(1500):
        t = base_time + i * 0.2
        pkt1 = Ether() / IP(src=local_ip, dst=remote_ip) / TCP(sport=41001, dport=443, flags="A") / ("X" * 50)
        pkt1.time = t
        packets.append(pkt1)

        pkt2 = Ether() / IP(src=remote_ip, dst=local_ip) / TCP(sport=443, dport=41001, flags="A") / ("Y" * 100)
        pkt2.time = t + 0.05
        packets.append(pkt2)

    wrpcap(filename, packets)
    print(f"Saved {len(packets)} packets to {filename}")

def generate_anomalous_pcap(filename):
    print(f"Generating anomalous traffic PCAP (Training with small packets + Exfiltration with massive 1500+ byte packets): {filename}...")
    packets = []
    base_time = 1790082000.0
    local_ip = "192.168.1.100"
    c2_ip = "10.0.0.66"

    # Phase 1: Small packets only (size bin 0 or 1: 0-64 or 65-128 bytes)
    for i in range(800):
        t = base_time + i * 0.1
        pkt = Ether() / IP(src=local_ip, dst=c2_ip) / TCP(sport=42000, dport=443, flags="A") / ("A" * 20)
        pkt.time = t
        packets.append(pkt)
        pkt_r = Ether() / IP(src=c2_ip, dst=local_ip) / TCP(sport=443, dport=42000, flags="A") / ("B" * 20)
        pkt_r.time = t + 0.02
        packets.append(pkt_r)

    # Phase 2: Massive jumbo/exfiltration packets (size bin 11: 1025+ bytes) never seen in training
    for i in range(800, 1500):
        t = base_time + i * 0.1
        if i % 4 == 0:
            # Massive packet (1500 bytes) -> falls in bin 11 (1025+ bytes), never seen in training!
            pkt_ex = Ether() / IP(src=local_ip, dst=c2_ip) / TCP(sport=42000, dport=443, flags="PA") / ("EXFIL" * 350)
            pkt_ex.time = t
            packets.append(pkt_ex)
        else:
            pkt_norm = Ether() / IP(src=local_ip, dst=c2_ip) / TCP(sport=42000, dport=443, flags="A") / ("A" * 20)
            pkt_norm.time = t
            packets.append(pkt_norm)

        pkt_resp = Ether() / IP(src=c2_ip, dst=local_ip) / TCP(sport=443, dport=42000, flags="A") / ("B" * 20)
        pkt_resp.time = t + 0.02
        packets.append(pkt_resp)

    wrpcap(filename, packets)
    print(f"Saved {len(packets)} packets to {filename}")

def generate_no_tls_quic_pcap(filename):
    print(f"Generating non-TLS/QUIC traffic PCAP (ICMP/HTTP/DNS only): {filename}...")
    packets = []
    base_time = 1790082000.0
    local_ip = "192.168.1.100"
    dns_ip = "8.8.8.8"

    for i in range(200):
        t = base_time + i * 0.2
        pkt = Ether() / IP(src=local_ip, dst=dns_ip) / UDP(sport=12345, dport=53) / ("DNS_QUERY" * 5)
        pkt.time = t
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Saved {len(packets)} packets to {filename}")

if __name__ == "__main__":
    generate_normal_pcap("normal_flow.pcap")
    generate_anomalous_pcap("anomalous_flow.pcap")
    print("Files generated!")
