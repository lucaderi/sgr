#! /usr/bin/env python

import time
import pyping
import rrdtool
import sys
import os.path
import getopt
from mailfunction import sendAlarm

ok=0

if len(sys.argv)<2 or len(sys.argv)>3 :
	 print 'argument error!\n'
         print 'usage ----> PingChecker.py -s <sleepTime>'
         print 'where sleepTime\nis the time (in second)\nbetween two consecutive ping session on the same host'
         print 'sleepTime must be >=5 and =<3600'
         sys.exit(2) 

if len(sys.argv)==2:
  if sys.argv[1]=="-h":
	 print 'usage ----> PingChecker.py -s <sleepTime>'
         print 'where sleepTime\nis the time (in second)\nbetween two consecutive ping session on the same host'
         print 'sleepTime must be >=5 and =<3600'
         sys.exit(2) 
  else:
  	 print 'argument error!\n'
         print 'usage ----> PingChecker.py -s <sleepTime>'
         print 'where sleepTime\nis the time (in second)\nbetween two consecutive ping session on the same host'
         print 'sleepTime must be >=5 and =<3600' 
         sys.exit(2) 
         
if len(sys.argv)==3:
  if sys.argv[1]=="-s":
	 ok=1
  else:
  	 print 'argument error!\n'
         print 'usage ----> PingChecker.py -s <sleepTime>'
         print 'where sleepTime\nis the time (in second)\nbetween two consecutive ping session on the same host'
         print 'sleepTime must be >=5 and =<3600' 
         sys.exit(2)  
         
# se arrivo qui sono con -s e qualcosa dopo         
try: 
      sleepTime = int(sys.argv[2])
except: 
      print("Invalid argument for -s")
      sys.exit(2)  
      
if sleepTime < 5 or sleepTime>3600:
      	print("Invalid argument for -s")
      	print 'sleepTime must be >=5 and =<3600'
      	sys.exit(2)           


scriptPath=os.path.dirname(os.path.realpath(sys.argv[0]))+"/"
  
print 'sleepTime is', sleepTime,"\n"
print "Welcome to PingToRRD!\n"

serverList = []
counterList = []

try:
 inputfile = open(scriptPath+'hostname.conf')
except: 
 print "unable to open the configuration file. Exit."
 sys.exit(2)
print "Host found in configuration file:"
for line in inputfile:
    prova = line
    prova = prova[:-1]
    print "- "+prova
    serverList.append(prova)
    counterList.append(0)
print "\n"

for e in serverList :
   if not os.path.isfile(scriptPath+e+"-"+str(sleepTime)+'.rrd') :
   	print(e+"-"+str(sleepTime)+".rrd file doesn't exists, I create it\n")
   	rrdtool.create(scriptPath+e+"-"+str(sleepTime)+'.rrd',
        '--start',str(int(time.time())),
        '--step', ''+str(sleepTime),
        'DS:min:GAUGE:3800:0:10000' ,
        'DS:avg:GAUGE:3800:0:10000' ,
        'DS:max:GAUGE:3800:0:10000' ,
        'RRA:MAX:0.5:1:525600')

try:
 while 1:
        start_time = time.time()
	
        i=0
	
	for i in range(len(serverList)):
	 try:
	 	response = pyping.ping(serverList[i])	
	 except KeyboardInterrupt:
        	print("\nLoop blocked by user")
        	sys.exit(0) 	
	 except: 		
	 	print("problem with Ping")
	 	print("check your internet connection")
	 	print("remember to run the script with administrator privileges")
	 	print("Exit")
	 	sys.exit()	

	 if response.ret_code == 0:
	 	
	 	counterList[i]=0
  		print serverList[i], 'is up!'
  		print("min/avg/max = "+response.min_rtt+"/"+response.avg_rtt+"/"+response.max_rtt+" ms\n")	
  		rrdtool.update(scriptPath+serverList[i]+"-"+str(sleepTime)+'.rrd',
  		str(int(time.time()))+':'+
  		response.min_rtt+':'+
  		response.avg_rtt+':'+
  		response.max_rtt
  		)
  		
	 else:
  		print serverList[i], 'is down!'
  		if counterList[i] < 101 :
  			counterList[i]=counterList[i]+1
  			if counterList[i] == 2  or counterList[i]%25==0:
  				try:
  					sendAlarm(serverList[i],str(counterList[i]))
  		                	print 'Mail Alarm\n'
  		                except KeyboardInterrupt:
        				raise	
  		                except  :
  		                	print 'WARNING --> Unable to send Alarm\n'
  		                	counterList[i]=0
  		        else:
  		        	print("")        	
  	
  	end_time=time.time()
	used_time=int(end_time - start_time)
  	thisSleepTime = sleepTime-used_time
  	if thisSleepTime >0:	                		
  	 	time.sleep(thisSleepTime) 
  	 	print("sleep for "+str(thisSleepTime))
  		 	
  	print("----------New polling cycle----------\n")
  	
except KeyboardInterrupt:
        	print("\nLoop blocked by user")
        	sys.exit(0)  	
  	
  	
