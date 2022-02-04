#!/usr/bin/python

import appfil
import subprocess
import sys
import structures

if len(sys.argv) == 1:
    print "Missing filter's file"
elif len(sys.argv) == 2:
    print "Missing IGMP's option "
else:
    doc = sys.argv[1]
    f = open(doc,'r')
    igmp_opt = sys.argv[2]
    alb = structures.Main_Structures()
    for line in f:
        tupla = line.split(',',4)
        protocol = tupla[0][1:]
        if protocol == 'None':
            protocol = None
        ip_dest = tupla[1][1:]
        if ip_dest == 'None':
           ip_dest = None
        port_dest = tupla[2][1:]
        if port_dest == 'None':
           port_dest = None
        else:
           port_dest = int(port_dest)
        ip_sender = tupla[3][1:]
        if ip_sender == 'None':
           ip_sender = None
        port_sender = tupla[4][1:-2]
        if port_sender == 'None':
           port_sender = None
        else:
           port_sender = int(port_sender)

        full_filt = (protocol, ip_dest, port_dest, ip_sender, port_sender)
        if not((full_filt[0] is None) and (full_filt[1] is None) and (full_filt[2] is None) and (full_filt[3] is None) and (full_filt[4] is None)):
            alb.insert(full_filt)

    print alb
    f.close()
    s = subprocess.Popen(['tcpdump', '-nv', '-i', 'any', 'ip'], stdout=subprocess.PIPE)
    while True:
        line1 = s.stdout.readline()
        line2 = s.stdout.readline()
        line = line1 + line2
        #if not line:
        #j = False
        #else:
        print appfil.st(alb,line,igmp_opt)

