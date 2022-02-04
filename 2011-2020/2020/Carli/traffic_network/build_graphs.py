#!/usr/bin/python3

#PYTHON SCRIPT TO BUILD A RRDGRAPH ABOUT TRAFFIC NETWORK AND BANDWIDTH USAGE

#IMPORT
import rrdtool
import sys
import os

print('Enter graph period: hh --> half hour, h --> hour, nh --> n hours, d --> day, w --> week')
inizio_grafico = input('Period: ')
print()

if(inizio_grafico == 'hh'):
	start = '-30min'
elif(inizio_grafico == 'h'):
	start = '-1h'
elif(inizio_grafico == 'nh'):
	start = '-' + input('Enter the interval time in hours --> ') + 'h'
elif(inizio_grafico == 'd'):
	start = '-1d'
elif(inizio_grafico == 'w'):
	start = '-1w'
else:
	print('\nIllegal value ... Try again!\n')
	sys.exit()

end = '-1s'

#FACCIO SCEGLIERE ALL'UTENTE QUALI GRAFICI OTTENERE IN BASE AI DB PRESENTI NELLA DIRECTORY CORRENTE
path = os.getcwd() #path della directory di lavoro corrente
cont = os.listdir(path) #lista di file e sottodirectory all'interno
file_ext = '.rrd' #estensione dei file di mio interesse
lista = [] #lista che uso per salvare i file.rrd

print('\nThe current directory contains the following files:')

for file in cont:
	if file.endswith(file_ext):
		print(f'---> {file}')
		lista.append(file)
		
filename = input('\nChoose the file.rrd you want the graphs for --> ')

if (filename not in lista):
	print('This file does not exist ... Try again!\n')
	sys.exit()
else:
	filename = os.path.splitext(filename)[0]

graph_traffic = f'{filename}.png'
graph_band = f'{filename}_band.png'
filename = f'{filename}.rrd'

#############################################################################################################################

interface = os.path.splitext(filename)[0]
width = '-w 1000'
height = '-h 400'
step = 10

#TRAFFIC NETWORK GRAPH
MIN_in = 'VDEF:min_in=in_bytes,MINIMUM'
MAX_in = 'VDEF:max_in=in_bytes,MAXIMUM'
AVG_in = 'VDEF:avg_in=in_bytes,AVERAGE'

MIN_out = 'VDEF:min_out=out_bytes,MINIMUM'
MAX_out = 'VDEF:max_out=out_bytes,MAXIMUM'
AVG_out = 'VDEF:avg_out=out_bytes,AVERAGE'

ninefivein = 'VDEF:ninefivein=input,95,PERCENT'
ninefiveout = 'VDEF:ninefiveout=output,95,PERCENT'


db = rrdtool.graph(graph_traffic,'--start',start,'--end',end,f'--title=TRAFFIC NETWORK ON {interface}',f'--vertical-label=Mbit',width,height,f'DEF:input={filename}:in:AVERAGE',f'DEF:output={filename}:out:AVERAGE','CDEF:in_bytes=input,1000000,/','CDEF:out_bytes=output,1000000,/',ninefivein,ninefiveout,'AREA:input#32CD32:Inbound  Traffic',MIN_in,'GPRINT:min_in: \tMin = %6.2lf Mb',MAX_in,'GPRINT:max_in: \tMax = %6.2lf Mb',AVG_in,'GPRINT:avg_in: \tAvg = %6.2lf Mb\\n','AREA:output#0000ff:Outbound Traffic',MIN_out,'GPRINT:min_out: \tMin = %6.2lf Mb',MAX_out,'GPRINT:max_out: \tMax = %6.2lf Mb',AVG_out,f'GPRINT:avg_out: \tAvg = %6.2lf Mb\\n','LINE:ninefivein#ff0000:95th percentile inbound traffic\\n','LINE:ninefiveout#8B0000:95th percentile outbound traffic') 

print(f'\nCreating the graph {graph_traffic} about traffic network')

#########################################################################################################################################


#BANDWIDTH USAGE GRAPH
MIN = 'VDEF:min=ris_mb,MINIMUM'
MAX = 'VDEF:max=ris_mb,MAXIMUM'
AVG = 'VDEF:avg=ris_mb,AVERAGE'

ninefive = 'VDEF:ninefive=ris,95,PERCENT'

db_1 = rrdtool.graph(graph_band,'--start',start,'--end',end,f'--title=BANDWIDTH USAGE ON {interface}',f'--vertical-label=Mbit',width,height,f'DEF:input={filename}:in:AVERAGE',f'DEF:output={filename}:out:AVERAGE','CDEF:sum=input,output,+',f'CDEF:ris=sum,{step},/','CDEF:ris_mb=ris,1000000,/','AREA:ris#FFFF00:Bandwidth Usage',MIN,'GPRINT:min: \tMin = %6.2lf Mb',MAX,'GPRINT:max: \tMax = %6.2lf Mb',AVG,'GPRINT:avg: \tAvg = %6.2lf Mb\\n',ninefive,'LINE:ninefive#ff0000:95th percentile bandwidth usage') 

print(f'Creating the graph {graph_band} about bandwidth usage\n')

##########################################################################################################################################


