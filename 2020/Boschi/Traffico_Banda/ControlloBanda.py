#!/usr/bin/python3

import sys
import rrdtool
import os.path
import os
import subprocess
from datetime import datetime
from time import sleep
from easysnmp import Session, snmp_get


#subprocess.call('export MIBS=all', shell=True) #non funziona :(
subprocess.call('clear', shell=True)

#Prendo da input host, community, e il numero di iterazioni
community=input('Inserisci la community: ')
host=input('Inserisci host: ')
version=2


#--------------------------------------------------------------------------------------


#controllo sui parametri presi da input
if(len(host)==0 or len(community)==0):
	print('Errore parametri.')
	sys.exit()


#--------------------------------------------------------------------------------------

#creo una sessione snmp, sulla quale farò le richieste get 
sessionSNMP=Session(hostname=host, community=community, version=version)

#--------------------------------------------------------------------------------------


#Selezione dell'interfaccia da monitorare
N_interface=int(sessionSNMP.get('ifNumber.0').value) #numero di interfacce presenti

#stampo le interfacce disponibili
print('INTERFACCE DISPONIBILI:')

for i in range (1, N_interface+1):
	interfaceName=sessionSNMP.get(f'ifName.{i}').value #nome dell'interfaccia con l'i-esimo indice
	print(f'\t{i} - {interfaceName}')

interface=int(input('Seleziona un\'interfaccia da monitorare: '))

#controllo sugli input
if(interface<1 or interface>(N_interface)):
	print('Interfaccia non valida!')
	sys.exit()

interfaceName=sessionSNMP.get(f'ifName.{interface}').value #nome dell'interfaccia selezionata

#INPUT IMPORTANTI
#	interfaceName: nome dell'interfaccia da monitorare
#	interface: 	   indice dell'interfaccia da monitorare


#--------------------------------------------------------------------------------------

#								CREAZIONE DEL DB CON RRDTOOL

step=10 #intervallo tra letture = 1 lettura ogni 10 secondi

#scrivo lo step sul file che alche il tool per la creazione dei grafici potra leggere
FileStep=open('step.txt', 'w')
FileStep.write(str(step))
FileStep.close()

#PRIMO ROUND ROBIN ARCHIVE: conterrà i valori letti della memoria   -->   Conterrà i dati dell'ultima ora 
monitoringTime_1=3600 #IN SECONDI: 1 ora di monitoraggio sui pacchetti unicast in entrata
Celle_1=str(int(monitoringTime_1/step)) #celle di memoria che mi servono per tenere i dati del monitoraggio negli ultimi monitoringTime_1 secondi

#SECONDO ROUND ROBIN ARCHIVE: conterrà la media al minuto dei valori del precedente RRA (cioè la media al minuto dei valori della memoria)
monitoringTime_2=60 #IN SECONDI: voglio la media ogni cinque minuti dei valori del RRA precedente.
NumValori_2=str(int(monitoringTime_2/step)) #il numero dei valori di RRA1 (quello con i valori "singoli" della memoria ) che mi servono per fare la media
Celle_2=4*7*24*60 #Tengo l'ultim mese di dati --> minuti in un mese:4*7*24*60 (voglio la media al minuto, quindi mi interessano i minuti)


maxVal=(2**32) -1 #massimo di pacchetti che passano in 5 secondi
maxTimetoWait=step*2 #massimo tempo per il quale attendo un pacchetto
valori_pred=Celle_1*2


nomeDB=f'{interfaceName}.rrd' #per ogni interfaccia credo un diverso database per monitorarla e salvare i dati

#contorllo se il file esiste o no
if(os.path.isfile(nomeDB)==False):
	database=rrdtool.create(nomeDB, '--step', str(step), f'DS:InOctets:COUNTER:{maxTimetoWait}:0:{maxVal}',f'DS:OutOctets:COUNTER:{maxTimetoWait}:0:{maxVal}',  f'RRA:AVERAGE:0.5:1:{Celle_1}', f'RRA:AVERAGE:0.5:{NumValori_2}:{Celle_2}',f'RRA:AVERAGE:0.5:1:{Celle_1}', f'RRA:AVERAGE:0.5:{NumValori_2}:{Celle_2}')#, f'RRA:HWPREDICT:{valori_pred}:0.1:0.0035:288')



#-----------------------------------------------------------------------------------------



#per stampare le statistiche a video (faccio manualmente la differenza)
precIN=0
precOUT=0

#for i in range(N):
try:
	
	while True:
		
		#prendo i bit in entrata e in uscita e ci faccio la update nel DB
		bitIN=8*int(sessionSNMP.get(f'ifInOctets.{interface}').value)
		bitOUT=8*int(sessionSNMP.get(f'ifOutOctets.{interface}').value)
		database=rrdtool.update(nomeDB, 'N:%s:%s' %(str(bitIN),str(bitOUT)) ) #metto il nuovo record nel database
		
		#------parte per stampare le statistiche a video

		#BIT_IN
		diffIN=abs(precIN-bitIN)
		bpsIN=int(diffIN/step)
		MbpsIN=round((bpsIN/(2**20)), 3)
		precIN=bitIN

		#BIT_OUT
		diffOUT=abs(precOUT-bitOUT)
		bpsOUT=int(diffOUT/step)
		MbpsOUT=round((bpsOUT/(2**20)), 3)
		precOUT=bitOUT

		#t=datetime.now().time().strftime('%H:%M:%S')
		subprocess.call('clear', shell=True)

		print(f'IN  (10s): {bitIN} bit || {bpsIN} bps || {MbpsIN} Mbps')
		print(f'OUT (10s): {bitOUT} bit || {bpsOUT} bps || {MbpsOUT} Mbps')

		sleep(step)


except KeyboardInterrupt:
	subprocess.call('clear', shell=True)
	print('Stopping data gathering.\nShutting down...')





























