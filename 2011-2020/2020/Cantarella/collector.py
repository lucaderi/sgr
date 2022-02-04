#!/usr/bin/python
import socket
from datetime import datetime
from unpacker import Unpacker
from clickhouse_driver import Client

"""
BYTES	CONTENTS	DESCRIPTION
0-3		srcaddr	Source IP address
4-7		dstaddr	Destination IP address
8-11	nexthop	IP address of next hop router
12-13	input	SNMP index of input interface
14-15	output	SNMP index of output interface
16-19	dPkts	Packets in the flow
20-23	dOctets	Total number of Layer 3 bytes in the packets of the flow
24-27	first	SysUptime at start of flow
28-31	last	SysUptime at the time the last packet of the flow was received
32-33	srcport	TCP/UDP source port number or equivalent
34-35	dstport	TCP/UDP destination port number or equivalent
36		pad1	Unused (zero) bytes
37		tcp_flags	Cumulative OR of TCP flags
38		prot	IP protocol type (for example, TCP = 6; UDP = 17)
39		tos	IP type of service (ToS)
40-41	src_as	Autonomous system number of the source, either origin or peer
42-43	dst_as	Autonomous system number of the destination, either origin or peer
44		src_mask	Source address prefix mask bits
45		dst_mask	Destination address prefix mask bits
46-47	pad2	Unused (zero) bytes
"""

client = Client('localhost')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
sock.bind(('0.0.0.0', 2055))
unpck = Unpacker.Unpacker()



while True:
    try:
        print('listening..')
        (packetbuf, addr) = sock.recvfrom(65535)

        version = unpck.unpackbufferint(packetbuf, 0, 2)
        totalrecord = unpck.unpackbufferint(packetbuf, 2, 2)
        sysuptime = unpck.unpackbufferint(packetbuf, 4, 4)
        unix_sec = unpck.unpackbufferint(packetbuf, 8, 4)
        unix_nsec = unpck.unpackbufferint(packetbuf, 12, 4)
        
        print('unix_sec {0}'.format(unix_sec))
        unix_nsec = unix_nsec / 1000000000
        print('unix_nsec {0}'.format(unix_nsec))
        # as per the Netflow version 5 Standard..
        if totalrecord < 1 or totalrecord > 30:
            raise Exception("Invalid Record Count!!!")
        print("Netflow Version: %i" % version)
        print("Total number of records: %i" % totalrecord)
        
        for recordcounter in range(0, totalrecord):
            # Adjusts the pointer to the appropriate record after the header .. header size  = 24, record size = 48
            recordpointer = 24 + (recordcounter * 48)
            print("==================\n")
            print("Record: %i" % recordcounter)
            srcaddr = socket.inet_ntoa(packetbuf[recordpointer:recordpointer + 4])
            
            print('SourceAddress {0}'.format(srcaddr))
            dstaddr = socket.inet_ntoa(packetbuf[recordpointer + 4:recordpointer + 8])
            
            print("Destination address: %s" % dstaddr)
            nxthp = socket.inet_ntoa(packetbuf[recordpointer + 8:recordpointer + 12])
            
            print("nexthop: %s" % nxthp)
            input_snmp = unpck.unpackbufferint(packetbuf, recordpointer + 12 , 2)
            output_snmp = unpck.unpackbufferint(packetbuf, recordpointer + 14, 2)
            
            print("input_snmp: %s" % input_snmp)
            print("output_snmp: %s" % output_snmp)
            # pointer has been adjusted to read the appropriate field in the netflow record
            dPkts = unpck.unpackbufferint(packetbuf, recordpointer + 16, 4)
            
            print('Total packets: {0}'.format(dPkts))
            dOctets = unpck.unpackbufferint(packetbuf, recordpointer + 20, 4)
            
            print('Total bytes {0} '.format(dOctets))
            startflow = unpck.unpackbufferint(packetbuf, recordpointer + 24, 4)
            endflow = unpck.unpackbufferint(packetbuf, recordpointer + 28, 4)
            startfl =   unix_sec + unix_nsec + 21600
            startflo = int(startfl)      
            data_flusso = datetime.fromtimestamp(startflo)           
            print('Data cattura del flusso {0}'.format(data_flusso))
            print('Endtime in seconds:{0}'.format(endflow))                      
            srcport = unpck.unpackbufferint(packetbuf, recordpointer + 32, 2)
            dstport = unpck.unpackbufferint(packetbuf, recordpointer + 34, 2)
            
            print("Source Port: %i" % srcport)
            print("Destination Port: %i" % dstport)
            l4protocol = unpck.unpackbufferint(packetbuf, recordpointer + 38, 1)
            
            
            if l4protocol == 6:
                l4proto = 'TCP'

            elif l4protocol == 17:
                l4proto = 'UDP'

            else:
                l4proto = 'Other'
            print("L4 protocol: %s" % l4proto)
            print("===================")
              
            
            
            client.execute('INSERT INTO netflowv5 (total_record_count, version, Data_flusso, srcaddr, dstaddr, next_hop, '
                           'snmp_input, snmp_output, number_packets, dOctets, last,'
                           'srcport, dstport, protocol) VALUES',
                           [(totalrecord, version,startflo, srcaddr, dstaddr, nxthp, input_snmp, output_snmp, dPkts, dOctets, endflow, srcport, dstport ,l4proto)])
            

    except Exception as e:
        print(e)
        break


