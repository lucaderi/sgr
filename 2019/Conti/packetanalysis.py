from scapy.all import *
import socket
import matplotlib.pyplot as plt
import numpy as np
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
localAddress = ""+s.getsockname()[0]


def pkt_analysis():
	packets = rdpcap('mypcap.pcap')

	dictionary = {}

	for pkt in packets:
		inData = 0
		ouData = 0
		payloadL = 0


		if Raw in pkt:
			payloadL = len(pkt[Raw])

		if IP in pkt:

			proto_field = pkt[IP].get_field('proto').i2s[pkt.proto]

			key = ""+pkt[IP].dst
			payloadL = pkt[IP].len
			if(key == localAddress):
				key = ""+pkt[IP].src
				inData += payloadL
			else:
				ouData += payloadL

			((tcpin,tcpou),(udpin,udpou)) = dictionary.get(key,((0,0),(0,0)))

			if(proto_field== "tcp"):
				tcpin += inData
				tcpou += ouData

			if(proto_field == "udp"):
				udpin += inData
				udpou += ouData

			dictionary.update({key: ((tcpin,tcpou),(udpin,udpou))})

	 
	x = dictionary.keys()

	valueslist = dictionary.values()

	totalTransf = []

	mlist = [[],[],[],[]]

	for ((tcpin,tcpou),(udpin,udpou)) in valueslist:
		mlist[0].append(tcpin)
		mlist[1].append(tcpou)
		mlist[2].append(udpin)
		mlist[3].append(udpou)
		totalTransf.append(tcpin+tcpou+udpin+udpou)

	ipOrdered = [x for _,x in sorted(zip(totalTransf,x))]
	mlist[0] = [x for _,x in sorted(zip(totalTransf,mlist[0]))]
	mlist[1] = [x for _,x in sorted(zip(totalTransf,mlist[1]))]
	mlist[2] = [x for _,x in sorted(zip(totalTransf,mlist[2]))]
	mlist[3] = [x for _,x in sorted(zip(totalTransf,mlist[3]))]

	xlabel = "Bytes"

	if max(totalTransf) > 1000000:
		mlist[0] = [x / 1000 for x in mlist[0]]
		mlist[1] = [x / 1000 for x in mlist[1]]
		mlist[2] = [x / 1000 for x in mlist[2]]
		mlist[3] = [x / 1000 for x in mlist[3]]
		totalTransf = [x / 1000 for x in totalTransf]
		xlabel = "KBytes"


	plt.barh(ipOrdered, mlist[0], color="red")
	plt.barh(ipOrdered, mlist[1], color="orange", left=mlist[0])
	plt.barh(ipOrdered, mlist[2], color="blue", left=mlist[1])
	plt.barh(ipOrdered, mlist[3], color="yellow", left=mlist[2])

	plt.gcf().subplots_adjust(bottom=0.40)

	colors = {'UDP IN':'blue', 'UDP OUT':'yellow', 'TCP IN':'red', 'TCP OUT':'orange'}         
	labels = list(colors.keys())
	handles = [plt.Rectangle((0,0),1,1, color=colors[label]) for label in labels]
	plt.legend(handles, labels)

	plt.xlabel(xlabel)
	plt.xticks(np.arange(0, max(totalTransf), max(totalTransf)/5))

	plt.tight_layout()
	plt.savefig('ima_final.png')

if len(sys.argv) < 3:
	print("invalid arguments, specify networkcard name and packet count")
	exit()
else :
	pkt = sniff(iface=sys.argv[1], prn=lambda x: x.summary(), count=int(sys.argv[2]))
	wrpcap('mypcap.pcap', pkt)
	pkt_analysis()
