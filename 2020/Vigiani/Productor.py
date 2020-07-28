from scapy.all import *
from threading import Condition


#Struttura Dati condivisa con il modulo Consumer
heap = []

#Variabile di condizionamento per ottenere la risorsa heap
lock = Condition()

#Dimensione massima della struttura dati heap
HEAP_MAX_PACKET = 10000


#
#	INSERIMENTO  PARAMETRI HEAP
#
def	elaboratePacket(packet):
	global heap
	global lock
	global HEAP_MAX_PACKET
	global current_num_packet


	#ACQUISIZIONE RISORSA
	lock.acquire()
	if len(heap) == HEAP_MAX_PACKET:
		lock.wait()


	#PUSH
	heap.append(packet[IP].src)


	#RILASCIO RISORSA
	lock.notify()
	lock.release()


#
#	GET LOCAL IP ADDRESS
#
def getLocalIP():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	s.connect(('<broadcast>', 0))
	return s.getsockname()[0]


#
#	CAPTURE PACKETS
#
def capture():
	#Get local ip address
	local_ip_address = getLocalIP()

	#Set Filters
	filters = "ip dst {}".format(local_ip_address)

	#
	#Start Capture Packet using Thread sniffer
	#This method is valid alone Scapy Version: 2.4.3+
	#
	sniffer = AsyncSniffer(filter=filters,prn=elaboratePacket)
	sniffer.start()


