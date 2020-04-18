import rrdtool
import os
import sys
from easysnmp import Session, snmp_get

#-----------------------------------------------------------------------------------------------------------------
#prendo in input il periodo su cui si vuole il grafico 

print("Seleziona periodo grafico:")
print("                          hh: half hour")
print("                           h: hour")
print("                           d: day")
print("                           w: week")
print("                           x: other (unity: hours)")

inizio=input("                       --->")

if(inizio=="hh"):
	startTime="-30min"
elif(inizio=="h"):
	startTime="-1h"
elif(inizio=="d"):
	startTime="-1d"
elif(inizio=="w"):
	startTime="-1w"
elif(inizio=="x"):
	startTime="-"+input("                           hours: ")+"h"

endTime="-1s"

larghezza="1000"
altezza="400"

#---------------------------------------------------

#l'utente mi deve dire di quale interfaccia vuole il grafico 

listaFile=os.listdir() #nomi dei file della cartella
listaInterfacce=[]

print('\n\nDATABASE DISPONIBILI:')

#mostro quali database l'utente può usare per il grafico 
for tmpFile in listaFile:
	if(tmpFile.endswith('.rrd')):
		print(f'\t{tmpFile}')
		listaInterfacce.append(tmpFile)

interfaceName=input('\n\nSelezionare il database da usare scrivendo il nome completo: ')

#controllo che l'input sia giusto
if((interfaceName in listaInterfacce)==False):
	print('Interfaccia non esistente o database dell\'interfaccia non presente.')
	sys.exit()

#elimino l'estensione .rrd dal nome del file
interfaceName=os.path.splitext(interfaceName)[0]



#ogni grafico sarà relativo a una certa interfaccia, e potra prendere i dati solo dal DB relativo a quella specifica interfaccia
nomeDB=f'{interfaceName}.rrd'
nome_grafico_traffico=f'Traffic_{interfaceName}.png'
nome_grafico_banda=f'Bandwidth_{interfaceName}.png'


#------------------------------------------------------


#byte in entrata
CDEF_MEGAbitIN='CDEF:byteIN=inputBit,1000000,/'

#minimo, massimo e media dei bit in entrata (valori espressi in Mbit)
minIN='VDEF:minIN=byteIN,MINIMUM'
maxIN='VDEF:maxIN=byteIN,MAXIMUM'
avgIN='VDEF:avgIN=byteIN,AVERAGE'


#minimo, massimo e media dei bit in uscita (valori espressi in Mbit)
CDEF_MEGAbitOUT='CDEF:byteOUT=outputBit,1000000,/'
minOUT='VDEF:minOUT=byteOUT,MINIMUM'
maxOUT='VDEF:maxOUT=byteOUT,MAXIMUM'
avgOUT='VDEF:avgOUT=byteOUT,AVERAGE'


#creazione del database del traffico (bit in, bit out e relativi max, min, avg)
database=rrdtool.graph(nome_grafico_traffico, '--start', startTime, '--end', endTime,"--title","Network Traffic",  f"-w {larghezza}", f"-h {altezza}", f'DEF:inputBit={nomeDB}:InOctets:AVERAGE',CDEF_MEGAbitIN, minIN, maxIN, avgIN, f'DEF:outputBit={nomeDB}:OutOctets:AVERAGE', CDEF_MEGAbitOUT, minOUT,maxOUT, avgOUT,  'VDEF:ninefiveIN=inputBit,95,PERCENT', 'COMMENT: Unit of measure\: Mbit \c', 'LINE2:inputBit#12b1ff:INPUT  TRAFFIC\t', 'GPRINT:minIN:MIN %6.4lf', 'GPRINT:maxIN:\tMAX %6.4lf', f"GPRINT:avgIN:\tAVG %6.4lf\\n", 'LINE2:outputBit#04c425:OUTPUT TRAFFIC\t', 'GPRINT:minOUT:MIN %6.4lf', 'GPRINT:maxOUT:\tMAX %6.4lf', f'GPRINT:avgOUT:\tAVG %6.4lf\\n', f'LINE1:ninefiveIN#fd6602:95% INPUT TRAFFIC')


#-----------------------------------------------------




#GRAFICO UTILIZZO BANDA (IN PERCENTUALE)-------------


#creo una sessione snmp, sulla quale farò le richieste get 

print('\n\nParametri SNMP')
com=input('Community: ')
host=input('Host: ')
sessionSNMP=Session(hostname=host, community=com, version=2)

N_interface=int(sessionSNMP.get('ifNumber.0').value) #numero di interfacce presenti
interfaceIndex=-1
for i in range (1, N_interface+1):
	ifNAME=sessionSNMP.get(f'ifName.{i}').value #nome dell'interfaccia con l'i-esimo indice
	if(ifNAME==interfaceName):
		interfaceIndex=i

if(interfaceIndex==-1):
	print("Errore con indici interfacce")
	sys.exit()

speed=0
speed=int(sessionSNMP.get(f'ifSpeed.{interfaceIndex}').value)

if(speed==0):
	speed=10000000

#apro il file su cui il tool che raccoglie i dati mi ha scritto quanto è lo step che sta utilizzando (per avere coerenza tra  questo tool e quello del database)
FileStep=open('step.txt', 'r')
step=int(FileStep.read()) #leggo tutto il contenuto (è solo il numero che rappresenta lo step)
divisore=step*speed


#definizioni di corstanti per usarle nella formula del calcolo della banda
inBit=f'DEF:inputBit={nomeDB}:InOctets:AVERAGE'
outBit=f'DEF:outputBit={nomeDB}:OutOctets:AVERAGE'
CDEF_in_out_bits='CDEF:in_out=inputBit,outputBit,+'
CDEF_in_out_bits_percent='CDEF:bits_percent=in_out,100,*'
CDEF_band=f'CDEF:banda=bits_percent,{divisore},/'

printing='AREA:banda#ffc800:Bandwidth utilization (%)'

#creazione del secondo grafico che rappresenta la percentuale di banda utilizzata
db2=rrdtool.graph(nome_grafico_banda,'--start', startTime, '--end', endTime,"--title","Bandwidth", "-u 100", "-z", "-l 0", "-r", "-M", "-A", f"-w {larghezza}", f"-h {altezza}", inBit, outBit, CDEF_in_out_bits,CDEF_in_out_bits_percent,CDEF_band, printing)



print('I grafici sono stati correttamente creati')






