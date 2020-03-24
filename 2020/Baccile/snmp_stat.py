#!/usr/bin/python3

#
# Installation Ubuntu:
# sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
# pip3 install easysnmp
# export MIBS=ALL
#

import sys
from easysnmp import Session
import time

# Default parameters
hostname = "localhost"
community = "public"
version = 1
requests = 5
t = 1

# Colors
request_c = "\033[1;42m"
title_c = "\033[1;32m"
reset_c = "\033[0;m"
empty_c = "\033[0;30m"
oid_c = "\033[0;36m"
type_c = "\033[0;33m"

# Print snmpwalk
def printStat(descr, items):
	print(title_c+"**********"+descr+"**********"+reset_c)
	if not items:
		print(empty_c+"(empty)"+reset_c)
	else:
		for i in items:
			print("{}{:<30} {}{:<10} = {}{:<10}".format(oid_c, i.oid, type_c, i.snmp_type, reset_c, i.value))
	print(title_c+"*******END "+descr+"**********"+reset_c+"\n")

# Parameters control
if len(sys.argv) == 1:
	print("Default start: hostname='localhost' community='public' version='1' request='5'")
elif len(sys.argv) < 4:
	print("Usage: python3 snmp_stat.py [hostname community version] [request]")
	sys.exit(0)
else:
	hostname = sys.argv[1]
	community = sys.argv[2]
	version = int(sys.argv[3])
	if len(sys.argv) == 5:
		requests = int(sys.argv[4])

session = Session(hostname=hostname, community=community, version=version)
for i in range(requests):
	print(request_c+"Start request "+str(i)+": "+time.ctime()+reset_c)
	printStat("CPU Stats", session.walk(".1.3.6.1.4.1.2021.11"))
	printStat("Memory Stats", session.walk(".1.3.6.1.4.1.2021.4"))
	print(request_c+"End request "+str(i)+reset_c+"\n")
	time.sleep(t)
