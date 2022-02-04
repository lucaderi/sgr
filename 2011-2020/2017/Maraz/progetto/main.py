
import threading
from collections import OrderedDict
import threading
import socket, sys
import re
from struct import *
from PyQt4 import QtCore, QtGui
import design
import time
from time import gmtime, strftime
from grapher import draw_graph


class LS_Gui(QtGui.QMainWindow, design.Ui_MainWindow):

    def __init__(self, parent=None):
        super(LS_Gui, self).__init__(parent)
        self.setupUi(self)

        #Vars
        self.networkrunning = [False]
        self.network_thread = [None]

        #Timer
        self.time = None

        #User ordered dict
        self.list_ips = OrderedDict()

        #Buttons
        self.pushButton.clicked.connect(self.start)
        self.pushButton_2.clicked.connect(self.stop)
        self.pushButton.setEnabled(True)
        self.pushButton_2.setEnabled(False)

        self.pushButton_3.clicked.connect(self.visualize)

        #List events
        self.listWidget.itemClicked.connect(self.load_ip_details)


    def network_loop(self):

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as msg:
            print "Socket could not be created. Error : "
            sys.exit()

        while self.networkrunning[0]:
            packet = s.recvfrom(65565)
            rawpacket=packet
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

                    summary = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(
                        sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size

                    data = packet[h_size:]
                    randstring=s_addr+"  -TCP->  "+d_addr+"  "+str(sequence)+"  seq "+str(len(rawpacket))+"b"
                    self.update_ip_dict(s_addr, summary, arrivetime, data, randstring,d_addr)
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

                    print s_addr +" -PING-> "+d_addr

                    self.update_ip_dict(s_addr, summary, arrivetime, data, s_addr + " -PING-> " + d_addr,d_addr)

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

                    randstring = s_addr+"  -U-D-P->  "+d_addr+" "+str(data_size)+"b"

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

                    self.update_ip_dict(s_addr, summary, arrivetime, data, randstring,d_addr)
                else:
                    pass

        print "Network loop stopped!"

    def load_ip_details(self,item):
        ip=item.text().split("    ")[0]
        entry=self.list_ips[str(ip)]

        self.listWidget_2.clear()
        for i in entry[3]:
            self.listWidget_2.addItem(i)

    def start(self):
        if not self.networkrunning[0]:
            self.time=time.time()
            self.networkrunning[0] = True
            self.network_thread[0] = threading.Thread(target=self.network_loop)
            self.network_thread[0].setDaemon(True)
            self.network_thread[0].start()
            self.pushButton_2.setEnabled(True)
            self.pushButton.setEnabled(False)
        else:
            pass

    def stop(self):
        self.networkrunning[0] = False
        self.pushButton.setEnabled(True)
        self.pushButton_2.setEnabled(False)

    def update_ip_gui(self):
        time.sleep(0.1)
        r=-1
        for ip,contents in self.list_ips.items():
            r=r+1
            i=self.listWidget.item(r)
            if i is not None:
                i.setText(ip+"    "+str(contents[1])+" B"+"    "+str(contents[2])+"    "+str(contents[0]))
            else:
                self.listWidget.addItem(ip+"    "+str(contents[1])+" B"+"    "+str(contents[2])+"    "+str(contents[0]))

    def update_ip_dict(self, s_addr, summary, stime, data, rawpacket,d_addr):
        if s_addr in self.list_ips.keys():
            l=self.list_ips[s_addr]
            d=l[4]

            if d_addr in d.keys():
                d[d_addr]=d[d_addr]+len(rawpacket)
            else:
                d[d_addr]=len(rawpacket)

            self.list_ips[s_addr]=[stime,l[1]+len(rawpacket),l[2]+1,l[3]+[rawpacket],d]
        else:
            d=OrderedDict()
            d[d_addr]=len(rawpacket)

            self.list_ips[s_addr]=[stime,len(rawpacket),1,[rawpacket],d]
        self.update_ip_gui()

    def visualize(self):

        self.stop()

        try:
            graph=[]
            edge_t=[]

            for s_ip,contents in self.list_ips.items():
                for d_ip,data in contents[4].items():
                    graph.append((s_ip,d_ip))
                    edge_t.append(data)


            #Scale down data - max 30
            limit = max(edge_t)
            maxwidth=35.0
            edge_t = [(float(d)/float(limit))*maxwidth  for d in edge_t ]


            #Sort by descending thickness
            n=zip(graph,edge_t)
            f=list(reversed(sorted(n, key=lambda x: x[1])))
            graph=[ip_pair for ip_pair,t in f]
            edge_t=[t for ip_pair,t in f]


            for i in range(0,len(graph)-1):
                first=graph[i][0]
                second=graph[i][1]
                if (second,first) in graph:
                    graph[i]="X"
                    edge_t[i]="X"

            graph=filter(lambda a: a != "X", graph)
            edge_t=filter(lambda a: a != "X", edge_t)


            draw_graph(graph, edge_t)

        except Exception as ex:
            print ex

def main():
    app = QtGui.QApplication(sys.argv)
    form = LS_Gui()
    form.show()
    app.exec_()

if __name__ == '__main__':
    main()
