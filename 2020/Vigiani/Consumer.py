import json
import requests
from collections import defaultdict
from Productor import heap
from Productor import lock
from Productor import HEAP_MAX_PACKET
from time import sleep


#Struttura dati data[IP]= <country,latitude,longitude,number_packet>
data = {}
data = defaultdict(lambda:("NaN",-1,-1,0),data)

# REST GET REQUEST
URL = 'http://ip-api.com/json/'


#
#	GET PACKET FROM HEAP
#
def getPacket():
	global heap
	global lock
	global HEAP_MAX_PACKET
	global current_num_packet


	# ACQUISIZIONE RISORSA
	lock.acquire()
	if len(heap) == 0:
		lock.wait()


	#POP
	packet_ip = heap.pop()


	#RILASCIO RISORSA
	lock.notify()
	lock.release()


	return packet_ip


#
#	Calculate Stats
#
def calculateStats(packet):
	global data


	if packet not in data.keys():
		try:
			response = requests.get(URL + packet)

			response_json = response.json()
			packet_country = response_json["countryCode"]
			packet_lat = response_json["lat"]
			packet_long = response_json["lon"]

			# Struttura dati data[IP]= <country,latitude,longitude,number_packet>
			data[packet] = (packet_country,packet_lat,packet_long,data[packet][3] + 1)

		except:
			pass

	else:
		data[packet] = (data[packet][0],data[packet][1],data[packet][2],data[packet][3] + 1)


#
#	MAIN LOOP
#
def elaborate():
	while True:
		packet_ip = getPacket()
		calculateStats(packet=packet_ip)


#
#	GET DATA PUT FLUXDB
#
def exportData():
	#with open('data.json', 'w') as outfile:
	#		json.dump(data,outfile)
	return data
