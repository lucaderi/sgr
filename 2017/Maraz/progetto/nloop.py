import threading
from collections import OrderedDict
import threading
import socket, sys
import re
from struct import *
from PyQt4 import QtCore, QtGui
import design
import time


def network_loop(self):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    while self.networkrunning[0]:
        packet = s.recvfrom(65565)
        rawpacket = packet
        packet = packet[0]

        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        arrivetime = strftime("%H:%M:%S", time.localtime())
        if eth_protocol == 8:

            ip_header = packet[eth_length:20 + eth_length]

            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # TCP protocol
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                summary = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(
                    dest_port) + ' Sequence Number : ' + str(
                    sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(
                    tcph_length)

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                data = packet[h_size:]
                randstring = s_addr + "  -TCP->  " + d_addr + "  " + str(sequence) + "  seq"
                self.update_ip_dict(s_addr, summary, arrivetime, data, randstring, d_addr)
            # ICMP Packets
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                summary = 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                data = packet[h_size:]

                print s_addr + " -PING-> " + d_addr

                self.update_ip_dict(s_addr, summary, arrivetime, data, s_addr + " -PING-> " + d_addr, d_addr)

            # UDP packets
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                summary = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
                    length) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                data = packet[h_size:]

                randstring = s_addr + "  -U-D-P->  " + d_addr + " " + str(data_size) + "b"

                if str(s_addr).startswith("192.168.1.") and str(d_addr).endswith(".254"):

                    string = str(data)
                    m = string[13:]
                    m = m[:-5]
                    m = list(m)
                    m[3] = "."
                    m = "".join(m)

                    p = re.compile("www\.\w+")

                    mlist = p.findall(m)

                    try:
                        m = mlist[0] + "." + m.split(mlist[0])[1][1:]
                    except Exception:
                        pass

                    if not len(m) == 0 and m.startswith("www"):
                        randstring = s_addr + "  -D-N-S->  " + d_addr + " : " + m
                        print randstring

                self.update_ip_dict(s_addr, summary, arrivetime, data, randstring, d_addr)
            else:
                pass

    print "Network loop stopped!"

network_loop()