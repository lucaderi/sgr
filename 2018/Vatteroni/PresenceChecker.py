#!/usr/bin/env python

#################################
#                               #
#       Presence Checker        #
#   Progetto Gestione di Rete   #
#          AA 2017/18           #
#                               #
#      Francesco Vatteroni      #
#                               #
#################################

import os
import sys
import time
import pcapy
import signal
import struct
import thread
import datetime
import traceback
from reprint import output
from threading import Thread
import xml.etree.ElementTree as ET
from impacket.ImpactDecoder import RadioTapDecoder, Dot11ControlDecoder, DataDecoder

ha={}
delay = 5 # delay per export
ignore = [] # mac da ignorare (ex. accesspoint della rete)
max_bytes = 256
read_timeout = 100
promiscuous = True
pacchetticatturati = 0
lastexport = datetime.datetime.now()
running = True
interface = ''
moninterface = ''
monitor_disable = 'airmon-ng stop '
monitor_enable  = 'airmon-ng start '
canale = 0 #canali da 1-13 (giro i numeri da 0-12)
directory = os.path.expanduser("~")
imprexc = None

#rotazione dei canali
def channelLoop(s):
    try:
        while(running):
            global canale
            canale = ((canale + 1) % 13)
            change_channel = 'iw dev '+moninterface+' set channel ' + str(canale+1)
            os.system(change_channel)
            time.sleep(s)
    except KeyboardInterrupt: raise

#stampa di "interfaccia"
def interfaceLoop(t,nprint):
    try:
        with output(output_type='dict') as output_lines:
            while(running):
                idict = dict(ha)
                PC = str(pacchetticatturati)
                LE = str(lastexport)
                ch = canale
                ee = str(imprexc)
                interfacedict = {}

                output_lines['Channel'] = "[{cc}] - Packet: [{pp}] - Interface: [{ii}]".format(cc=ch, pp=PC, ii=moninterface)
                output_lines['Last Export'] = "[{le}]".format(le=LE)
                output_lines['Debug'] = "[{exc}]".format(exc = ee)

                for k in idict:
                    interfacedict[k] = idict.get(k)[-1][1]

                if (nprint > 0):
                    ssize = min(nprint, len(interfacedict))
                else:
                    ssize = len(interfacedict)

                sorted_d = sorted(interfacedict.items(), key=lambda x: x[1])

                for i in range(0,ssize):
                    k = sorted_d[i][0]
                    s = sorted_d[i][1]
                    output_lines[i] = "MAC: {mc} - Signal: {sg}".format(mc = k, sg = s)

                time.sleep(t)
    except KeyboardInterrupt: raise

#formattazione MAC
def addressDecode(x):
    s = ""
    aux = [None] * 6
    for i in range(0,6):
        #salto i primi 8 byte per ottenere il mac trasmittente
        aux[i] = hex(x.get_byte(8+i))[2:]
    s = ':'.join(aux)
    return s

#scrittura su file
def exporter(haexport):
    name = directory + "/prschk "+ str(lastexport) +".log.xml"

    root = ET.Element("root")
    for h in haexport:
        doc = ET.SubElement(root, h)
        idx = 0
        for n in haexport.get(h):
            t = n[0]
            i = n[1]
            tup = ET.SubElement(doc, str(idx))
            ET.SubElement(tup, "time").text = str(t)
            ET.SubElement(tup, "intensify").text = str(i)
            idx = idx + 1

    tree = ET.ElementTree(root)
    tree.write(name)

#scrittura su file di eventuali eccezioni impreviste
def exporterException(ee):
    s = str(ee) + "\n"
    with open('Debug.log', mode='a') as contents:
        contents.write(s)

# callback per ricevere pacchetti
def recv_pkts(hdr, data):
    global lastexport
    global ha
    global pacchetticatturati
    try:
        #decodifica del pacchetto
        radio = RadioTapDecoder().decode(data)
        datadown = radio.get_body_as_string()
        ethe = Dot11ControlDecoder().decode(datadown)
        datadowndown = ethe.get_body_as_string()
        decodedDataDownDown = DataDecoder().decode(datadowndown)

        macS = (addressDecode(decodedDataDownDown))
        s = type(radio.get_dBm_ant_signal())

        time = datetime.datetime.now()

        #aggiunta al dizionario
        #controllo se il segnale ha un valore consistente, in caso contrario scarto
        if (s is int):
            signal = str(-(256 - radio.get_dBm_ant_signal()))+ " dB"
            t = (time,signal)
            if (ha.has_key(macS)):
                ha.get(macS).append(t)
            else:
                l = [t]
                ha[macS] = l
            pacchetticatturati = pacchetticatturati + 1

        #esporta su file (thread in parallelo)
        if ((time - lastexport).seconds > delay) & len(ha.keys()) :
            haexport = ha
            ha = {}
            lastexport = time
            thread.start_new_thread(exporter, (haexport, ) )
    
    except KeyboardInterrupt: raise
    except struct.error: pass #perche non lanciano eccezioni custom quelli di Impacket
    except: 
        #per evitare che crashi qual'ora ci siano errori imprevisti, ne tengo traccia per il debug
        global imprexc
        _, exc_obj, exc_tb = sys.exc_info()
        imprexc = (exc_obj, exc_tb.tb_lineno)
        thread.start_new_thread(exporterException, (imprexc, ) )

def mysniff(interface):
    global ignore

    pcapy.findalldevs()
    pc = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)
    #ignoro i tipi che non hanno mac sorgente
    filt = 'not(subtype ack or subtype cts)'
    #aggiungo i mac da ignorare
    for e in ignore:
        filt = filt + ' and wlan addr2 not ' + e
    pc.setfilter(filt)
    packet_limit = -1 # -1 per infiniti
    pc.loop(packet_limit, recv_pkts) # cattura pacchetti

def main():
    
    global ignore
    global running
    global directory
    global interface
    global moninterface
    global monitor_enable
    global monitor_disable

    interfaces = os.listdir('/sys/class/net/')
    
    if (len(sys.argv) == 2) and (sys.argv[1] in interfaces) or ((len(sys.argv) == 3) and (sys.argv[1] in interfaces) and (os.path.isfile(sys.argv[2]))):
        interface = sys.argv[1]

        #cartella per export
        directory = directory + "/PresenceCheckerLOG/" + interface
        if not os.path.exists(directory):
            os.makedirs(directory)

        moninterface = interface # + 'mon'
        monitor_enable = monitor_enable + interface + ';'
        monitor_disable = monitor_disable + moninterface + ';'

        if len(sys.argv) == 3:
            tree = ET.parse(sys.argv[2])
            root = tree.getroot() 

            for child in root:
                ignore.append(child.text)

        #os.system(monitor_enable)
        t1 = Thread(target=channelLoop, args=(0.1,))
        t2 = Thread(target=interfaceLoop, args=(0.5,10))

        try:
            t1.start()
            t2.start()
            mysniff(moninterface)
        except KeyboardInterrupt: 
            running = False
        finally:
            t1.join()
            t2.join()
            #os.system(monitor_disable)
            sys.exit()
    else:
        print '[!] Insert a valid interface or a valid ignore file'
        print '[!] example: python ' + sys.argv[0] + ' wlan0mon'
        print '[!] example: python ' + sys.argv[0] + ' wlan0mon ./ignore.xml'

main()