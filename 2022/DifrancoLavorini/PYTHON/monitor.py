from prometheus_client import start_http_server, Summary
from prometheus_client import Gauge
from easysnmp import Session, snmp_get, exceptions
import time
import math

#creazione di una sessione per usare snmp con easysnmp
session = Session(hostname='localhost', community='public', version=2)

start_http_server(8000)

cpuG = Gauge('cpu', 'utilizzo della cpu')
cpuUpG = Gauge('cpuup', 'upper bound SeS per la cpu')
cpuLowG = Gauge('cpulow', 'lower bound SeS per la cpu')
ramG = Gauge('ram', 'utilizzo della ram')
ramUpG = Gauge('ramup', 'upper bound SeS per la ram')
ramLowG = Gauge('ramlow', 'lower bound SeS per la ram')



#valore per il single exponential smoothing
alpha = 0.5
ro = 2.5


CPU_USAGE_OID = 'hrProcessorLoad'


RAM_TOTAL = '1.3.6.1.4.1.2021.4.5.0'
RAM_USAGE = '1.3.6.1.4.1.2021.4.6.0'
RAM_FREE = '.1.3.6.1.4.1.2021.4.11.0'


#walk per la cpu perché prendo l'utilizzo di ogni core
cpuusage = session.walk(CPU_USAGE_OID)
#per ogni core stampo la percentuale di utilizzo
a = 0
cputotusage = 0
for i in cpuusage:
    a=a+1
    curcore = 'core'+str(a)
    print(curcore, ' = ' ,i.value, '%')
    cputotusage += int(i.value)
#calcolo media utilizzo cpu tra i core
avgcpuusage = [cputotusage/a]
print('avg cpu usage: ', avgcpuusage[-1])
mostRecentCPUPredValue = avgcpuusage[-1]
mostRecentCPUValue = avgcpuusage[-1]
cpuPredictedValue = alpha * mostRecentCPUValue + (1-alpha) * mostRecentCPUPredValue
print('cpu Predicted Value: ', cpuPredictedValue)
avgcpuusagePred = [cpuPredictedValue]


ramtotal = session.get(RAM_TOTAL)
print('ram total: ', ramtotal.value)
ramused = session.get(RAM_USAGE)
print('ram used: ', ramused.value)
ramshared = session.get('.1.3.6.1.4.1.2021.4.13.0')
print('ram shared: ', ramshared.value)
rambuffered = session.get('.1.3.6.1.4.1.2021.4.14.0')
print('ram buffered: ', rambuffered.value)
ramtotalcached = session.get('.1.3.6.1.4.1.2021.4.15.0')
print('ram tot cached: ', ramtotalcached.value)
ramfree = session.get(RAM_FREE)
print('ram free: ' , ramfree.value)




ramUsedPerc = (int(ramtotal.value)-int(ramfree.value))/int(ramtotal.value)*100
print('ram used percentage: ' , ramUsedPerc)
ramUsedtotPerc = (int(ramused.value)+int(ramtotalcached.value))/int(ramtotal.value)*100
print('ram used percentage: ' , ramUsedtotPerc)

ramUsedArray = [ramUsedPerc]
ramPredictedValue = ramUsedPerc
ramPredictedArray = [ramPredictedValue]


while True:
	time.sleep(2)
	
	#cpu usage
	cpuusage = session.walk(CPU_USAGE_OID)
	#per ogni core stampo la percentuale di utilizzo
	a = 0
	cputotusage = 0
	for i in cpuusage:
		a=a+1
		curcore = 'core'+str(a)
		print(curcore, ' = ' ,i.value, '%')
		cputotusage += int(i.value)
	avgcpuusage.append(cputotusage/a)
	print('avg cpu usage: ', avgcpuusage[-1])
	mostRecentCPUPredValue = round(cpuPredictedValue,1)
	mostRecentCPUValue = avgcpuusage[-1]
	#calcolo Single exponential smoothing
	cpuPredictedValue = round(alpha * mostRecentCPUValue + (1-alpha) * mostRecentCPUPredValue, 1)
	print('cpu Predicted Value: ', cpuPredictedValue)
	avgcpuusagePred.append(cpuPredictedValue)

	#calcolo lower e upper bound
	cpuerror = cpuPredictedValue - mostRecentCPUPredValue;
	sumcpuerror = 0
	j=0
	for x in avgcpuusage:
		sumcpuerror += (avgcpuusage[j] - avgcpuusagePred[j])**2
		j=j+1
	cpuconfidence = round(math.sqrt(sumcpuerror/(len(avgcpuusage)+1)),1)
	cpuLowerBound = cpuPredictedValue - cpuconfidence * ro
	cpuUpperBound = cpuPredictedValue + cpuconfidence * ro 
	
	#invio dati su localhost:8000
	cpuG.set(avgcpuusage[-1])
	cpuLowG.set(cpuLowerBound)
	cpuUpG.set(cpuUpperBound)
	
	#ram usage
	ramtotal = session.get(RAM_TOTAL)
	ramused = session.get(RAM_USAGE)
	ramfree = session.get(RAM_FREE)
	ramUsedPerc = round((int(ramtotal.value)-int(ramfree.value))/int(ramtotal.value)*100,1)
	print('ram used percentage: ', ramUsedPerc)
	ramUsedArray.append(ramUsedPerc)
	mostRecentRamPredValue = ramPredictedValue
	mostRecentRamValue = ramUsedArray[-1]
	#Single Exponential smoothing per RAM
	ramPredictedValue = round(alpha * int(mostRecentRamValue) + (1-alpha) * int(mostRecentRamPredValue),1)
	print('ram used predicted: ', ramPredictedValue)
	ramPredictedArray.append(ramPredictedValue)


	#calcolo lower e upper bound
	ramerror = ramPredictedValue - mostRecentRamPredValue;
	sumramerror = 0
	j=0
	for x in ramUsedArray:
		sumramerror += (ramUsedArray[j] - ramPredictedArray[j])**2
		j=j+1
	ramconfidence = round(math.sqrt(sumramerror/(len(ramUsedArray)+1)),1)
	ramLowerBound = ramPredictedValue - ramconfidence * ro
	ramUpperBound = ramPredictedValue + ramconfidence * ro
	
	#invio dati su localhost:8000
	ramG.set(ramUsedArray[-1])
	ramLowG.set(ramLowerBound)
	ramUpG.set(ramUpperBound)
