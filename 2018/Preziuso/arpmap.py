import sys

import pyshark
from pyshark import LiveCapture

from interfaces import interfaces
from interfaces import default


# extract packets' info from captured data
def gen_arp_communications_matrix(data: LiveCapture):
	arp_communications_matrix = {}
	
	while True:
		try:
			pkt = data.next_packet()
			
			pkt_key = pkt.arp.src_proto_ipv4 + "." + pkt.arp.dst_proto_ipv4
			if pkt_key in arp_communications_matrix:
				old_rec = arp_communications_matrix[pkt_key]
				arp_communications_matrix[pkt_key] = (old_rec[0], old_rec[1], old_rec[2] + 1, int(old_rec[3]) + int(pkt.length))
			else:
				arp_communications_matrix[pkt_key] = (pkt.arp.src_proto_ipv4, pkt.arp.dst_proto_ipv4, 1, pkt.length)
			
		except StopIteration:
			break
			
	return arp_communications_matrix


# read interface from args
interface = sys.argv[1] if len(sys.argv) > 1 else default
if len(sys.argv) <= 1:
	print("Interface not specified!\nMonitoring default interface.\n", file=sys.stderr)

if interface not in interfaces:
	print("Interface not supported!\n\nSupported interfaces:", file=sys.stderr)
	for i_key in interfaces:
		print("- " + i_key, file=sys.stderr)
	quit(1)

# capture setup
capture = pyshark.LiveCapture(interface=interfaces[interface], bpf_filter='arp')

print("Scanning for ARP packets over " + interface + "...")
try:
	# capture
	capture.sniff()
except KeyboardInterrupt:
	
	# format and print results
	print("\nCaptured packets: ", len(capture), "\n")
	
	communications_matrix = gen_arp_communications_matrix(capture)
	
	print("\n\t", "Source", "\t|\t", "Destination", "\t|\t", "# Packets", "\t|\t", "# Bytes\n")
	for comm in communications_matrix.values():
		print("\t", comm[0], "\t|\t", comm[1], "\t|\t", comm[2], "\t|\t", comm[3])
