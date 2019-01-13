import sys

import pyshark
from pyshark import LiveCapture
from pyshark.tshark.tshark import get_tshark_interfaces

# default interface to scan
default = 'en0'


# check selected interface goodness
def check_interface(i):
	parameters = [pyshark.tshark.tshark.get_process_path(), '-D']
	tshark_interfaces = pyshark.tshark.tshark.check_output(parameters, stderr=None).decode("utf-8")
	interfaces = tshark_interfaces.splitlines()
	
	for inter in interfaces:
		if i == inter.split(' ')[1]:
			return
		
	print("Unknown interface!\n")
	print(tshark_interfaces, file=sys.stderr)
	quit(1)


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


# interface selection
if len(sys.argv) > 1:
	interface = sys.argv[1]
else:
	print("Interface not specified! Monitoring default interface.\n", file=sys.stderr)
	interface = default

check_interface(interface)

# capture setup
capture = pyshark.LiveCapture(interface=interface, bpf_filter='arp')

print("Scanning for ARP packets over interface \'" + interface + "\'...")
try:
	# capture
	capture.sniff()
except KeyboardInterrupt:
	
	# format and print results
	print("\n\tCaptured packets: ", len(capture), "\n")
	
	communication_matrix = gen_arp_communications_matrix(capture)
	
	dash = '-' * 72
	print(dash)
	print('{:^20}{:^20}{:^15}{:^15}'.format("SOURCE", "DESTINATION", "# PACKETS", "# BYTES"))
	print(dash)
	for comm in communication_matrix:
		print('{:<20}{:<20}{:>15}{:>15}'.format(comm[0], comm[1], comm[2], comm[3]))
