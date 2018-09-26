#!/usr/bin/env python

#################################
#                               #
#        Prschk Analyzer        #
#                               #
#      Francesco Vatteroni      #
#                               #
#################################

import os
import sys
import matplotlib.pyplot as plt
import xml.etree.ElementTree as ET
from datetime import datetime,  timedelta

value = {}

def printUsage(n):
    print '[!] ' + n + ' [Folder Path] [MAC]'

def printGrap(d,m):
    x = []
    y = []
    last_d = None
    i = 0
    s = 0
    if d.has_key(m):
        d[m].sort(key=lambda tup: tup[0])
        for e in d[m]:
            current_d = datetime.strptime(e[0][:-7],'%Y-%m-%d %H:%M:%S')
            if (last_d is not None) and (last_d - current_d) == timedelta(0):
                i = i+1
                s = s+int(e[1][:-3])
            else :
                if (last_d is not None):
                    x.append(last_d)
                    y.append(s/i)
                last_d = current_d
                i = 1
                s = int(e[1][:-3])
        plt.xticks(rotation = 30)
        plt.yticks(rotation = 30)
        plt.plot(x, y)
        plt.show()
    else:
        print "[!] MAC not found"

def parseAll(path):
    global value
    os.chdir(path)
    for filename in os.listdir(path):
        if filename.endswith('.xml'):
            fullname = filename
            root = ET.parse(fullname).getroot()
            for child in root:
                k = child.attrib.get('value')
                for el in child:
                    time = el[0].text
                    intes = el[1].text
                    t = (time, intes)
                    if value.has_key(k):
                        value.get(k).append(t)
                    else:
                        l = [t]
                        value[k] = l
            

def main():
    if ((len(sys.argv) != 3) or not(os.path.isdir(sys.argv[1]))):
        printUsage(sys.argv[0])
        sys.exit()
    else:
        parseAll(sys.argv[1])
        if len(value) != 0:
            printGrap(value, sys.argv[2])
        else:
            print "[!] No Files"


main()