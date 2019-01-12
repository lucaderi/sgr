import sys

import pyshark
from pyshark import LiveCapture

# default interface to scan
default = 'en0'


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
	
	def get_key(p):
		return p[2]
	
	return sorted(arp_communications_matrix.values(), key=get_key, reverse=True)


# read interface from args
if len(sys.argv) > 1:
	interface = sys.argv[1]
else:
	print("Interface not specified! Monitoring default interface.\n", file=sys.stderr)
	interface = default
	
# capture setup
capture = pyshark.LiveCapture(interface=interface, bpf_filter='arp')

print("Scanning for ARP packets over interface \'" + interface + "\'...")
try:
	# capture
	capture.sniff()
except KeyboardInterrupt:
	
	# format and print results
	print("\n\tCaptured packets: ", len(capture), "\n")
	
	print("\n\t", "Source", "\t\t|", "Destination", "\t\t|", "# Pkts", "\t|", "# Bytes\n")
	for comm in gen_arp_communications_matrix(capture):
		print("\t", comm[0], "\t\t|", comm[1], "\t\t|", comm[2], "\t\t|", comm[3])
