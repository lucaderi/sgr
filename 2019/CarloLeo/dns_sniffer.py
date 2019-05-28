import pyshark
import asyncio
import signal
import sys
import operator
import time
from pyshark.packet.packet import Packet
from storage import *

n = -1;
def usage():
	print("sudo dns_sniffer.py  -i [interfaccia] -m [minuti] -n [numero top request]")

if("-h" in sys.argv):
	usage()
	sys.exit(0)

if len(sys.argv) != 7: #controllo il numero di parametri
	print("Numero di parametri errati")
	usage()
	sys.exit(0)


nome_scrip, first_option, interface, second_option, minuti, thrid_option, n = sys.argv #prendo parametri


#controllo opzioni

if first_option != "-i" or second_option != "-m" or thrid_option != "-n":
	print("Opzione sbagliata")
	usage()
	sys.exit(0)

#converto i minuti in secondi
try:
	tmp = float(minuti)
	t = int(tmp * 60)
except ValueError :
		print("Argomento: "+minuti+" non valido")
		usage()
		sys.exit(1)

try:
	n = int(n)
except ValueError :
		print("Argomento: "+n+" non valido")
		usage()
		sys.exit(1)		


#istanzio oggetto per la cattura
cap = pyshark.LiveCapture(interface=interface,bpf_filter='udp port 53 or tcp port 53') #filitro i pacchetti dns 





stg = Storage() #istanzio un oggetto Storage

#funzione per la gestione dei pacchetti
def handler_pkt ( pkt ) : 
	byte = int(pkt.length) #aggiungo lunghezza del pacchetto
	stg.updateV(b=byte)
	if (int(pkt.udp.port) != 53 and int(pkt.dns.qry_type) == 1) : #prendo le richieste (filtro in base alla porta sorgente e al tipo di record che è richiesto [A])
		print('DNS request from: '+pkt.ip.src + " for name: "+ pkt.dns.qry_name)
		stg.updateStorage(name=pkt.dns.qry_name) #aggiorno dati statistici
		
	
	
def findTop(l,n):
	top = sorted(l,key=lambda kv:kv[1],reverse=True) #ordino gli oggetti in ordine crescente di occorrenze
	first = 1
	max_m = -1 #inizializzo il massimo
	#print("TOP")
	#print(top)
	print("*************************************************************************")
	print("Top richieste al DNS: ")
	print("(nome, numero di richieste)")
	print("-------------------------------------------------------------------------")
	if len(top) == 0:
		print("Non sono state rilevate richieste DNS sull interfaccia: "+interface)
	else:	
		for t in top:
			if n > 0: 
			 	n -= 1
			 	if t[1] != max_m: #aggiorno il massimo in modo da stampare tutti i nomi con lo stesso numero di occorrenze
			 		max_m = t[1]

			if n == 0 and t[1] != max_m: break #ho stampato gli n top richiesti, se n è maggiore delle richieste trovate stampo tutta la lista
			print(t)


def printResult():
	findTop(stg.getList(),n)
	print("Volume del traffico DNS: "+str(stg.getV())+" byte")



take = 1;
t0 = -1;
while 1:
	try:
		print("Live capture start")
		cap.apply_on_packets(handler_pkt,timeout=t) #apro cattura live
	except AttributeError:
		print("Pacchetto malformato statistiche calcolate: ")
		printResult()
		sys.exit(1)	
	except (KeyboardInterrupt,asyncio.TimeoutError,RuntimeError):
		printResult()
		sys.exit(0)