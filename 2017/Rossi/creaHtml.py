#! /usr/bin/env python

import os.path
import sys

def create():
 
 scriptPath=os.path.dirname(os.path.realpath(sys.argv[0]))+"/"
 try:
   inputfile = open(scriptPath+'hostname.conf')
 except: 
   print "unable to open the configuration file. Exit."
   sys.exit(2)
 
 message = """<!DOCTYPE html>
 <html>
 <head>
 <title>PingChecker</title>
 </head>
 <body>
 """
#per ogni host trovato nel file di configurazione, mostra un titolo e il grafico
 for line in inputfile:
    prova = line
    prova = prova[:-1]
    print prova
    message=message + '<center><h2>'+prova+' Ping</h2></center>'
    message=message + '<center><img src="'+prova+'-graph.png"></center>'

 message = message +"""
 </body>
 </html>"""

 f = open('graphViewer.html','w')
 f.write(message)
 f.close()  



