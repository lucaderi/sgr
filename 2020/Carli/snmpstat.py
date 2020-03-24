#!/usr/bin/python3

#PYTHON SCRIPT TO MONITOR CPU LOAD AND MEMORY USAGE WITH SNMP AGENT

#IMPORT
import sys
import time
from time import sleep
from easysnmp import Session, snmp_get


#PARAMETERS CHECK
community = input('Enter the community --> ') 
hostname = input('Enter hostname --> ')
num_iter = input('Enter the number of iterations --> ')
version = '2'

if (len(community)==0 or len(hostname)==0):
	print('Invalid parameters ... Try again!')
	sys.exit()

version = int(version)
num_iter = int(num_iter)

if(num_iter <= 0):
	print('This parameter must be positive ... Try again!')

###################################################


#CPU LOAD
def CPU_load(session):
	print('[CPU LOAD]')

	CPU_1minuteload = session.get('laLoad.1') #UDC-SNMP-MIB::laLoad.1
	CPU_5minuteload = session.get('laLoad.2')  #UDC-SNMP-MIB::laLoad.2
	CPU_10minuteload = session.get('laLoad.3')  #UDC-SNMP-MIB::laLoad.3

	print('1 minute load: ' + CPU_1minuteload.value)
	print('5 minute load: ' + CPU_5minuteload.value)
	print('10 minute load: ' + CPU_10minuteload.value + '\n')

#####################################################


#MEMORY STATS
def MEM_stats(session):
	print('[MEMORY STATISTICS]')

	MEM_tot = session.get('memTotalReal.0')  #UDC-SNMP-MIB::memTotalReal.0
	MEM_avail = session.get('memAvailReal.0') #UDC-SNMP-MIB::AvailReal.0
	MEM_buff = session.get('memBuffer.0') #UDC-SNMP-MIB::memBuffer.0
	MEM_cache = session.get('memCached.0') #UDC-SNMP-MIB::memCached.0

	print('Total:    ' + MEM_tot.value + ' kB')
	print('Available: ' + MEM_avail.value + ' kB')
	print('Buffered:   ' + MEM_buff.value + ' kB')
	print('Cached:   ' + MEM_cache.value + ' kB')

#####################################################


session = Session(hostname=hostname,community=community,version=version) #SNMP SESSION

for i in range(num_iter):
	print('\n' + str(i+1) + ') ' + time.ctime())
	print('************ REPORT ************')
	CPU_load(session)
	MEM_stats(session)
	print('********** END OF REPORT **********\n\n')
	sleep(5)

