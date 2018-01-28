#! /usr/bin/env python

import rrdtool
import sys
import os
import time
from datetime import datetime
from creaHtml import create

if len(sys.argv)<>2 :
	print("you must provide one numeric argument, the same you provide to PingChecker")
        print("usage  ---> doGraph.py number")
        print("es  ---> doGraph.py 75")
        sys.exit(2) 

try:
  second=int(sys.argv[1])        
except:
  print("you must provide one numeric argument, the same you provide to PingChecker")
  print("usage  ---> doGraph.py number")
  print("es  ---> doGraph.py 75")
  sys.exit(2) 
  
if second<5 or second>3600:  
  print("you must provide a number 4<n<3601")
  sys.exit(2)  

#qui dentro second ho un numero accettabile

#creo intanto la pagina html
create()

scriptPath=os.path.dirname(os.path.realpath(sys.argv[0]))+"/"

serverList = []

try:
 inputfile = open(scriptPath+'hostname.conf')
except: 
 print "unable to open the configuration file. Exit."
 sys.exit(2)
print "Host trovati nel file di configurazione:"
for line in inputfile:
    prova = line
    prova = prova[:-1]
    print "- "+prova
    serverList.append(prova)
print "\n"

graphTime=second*100

try:
 while 1:
       for e in serverList :
   	if not os.path.isfile(scriptPath+e+"-"+str(second)+'.rrd') :
   	   print(e+"-"+str(second)+".rrd file non presente")
           print("non posso creare il grafico. Esco")
           sys.exit(2)
        else:
          print("Nuovo grafico!!!"+e)
  	  rrdtool.graph(e+'-graph.png', '--title', 'Ping', '--width', '800', '--height', '200', '--start', 'end-'+str(graphTime)+'s',
  	 'DEF:min='+e+"-"+str(second)+'.rrd:min:MAX',
  		'DEF:avg='+e+"-"+str(second)+'.rrd:avg:MAX',
  		'DEF:max='+e+"-"+str(second)+'.rrd:max:MAX',
  		'COMMENT:Time '+datetime.now().strftime('%Y-%m-%d %H.%M.%S') ,
  		'LINE2:min#33FF99:min' ,
'LINE2:avg#FFFF00:avg' ,
'LINE2:max#FF3300:max')   
           
       print("------")   
       time.sleep(second/2)        
except KeyboardInterrupt:
        	print("\nLoop del programma bloccato dall'utente")
        	sys.exit(0)
