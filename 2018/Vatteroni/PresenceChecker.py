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
import thread
import datetime
import xml.etree.ElementTree as ET
from impacket.ImpactDecoder import RadioTapDecoder, Dot11ControlDecoder, DataDecoder

interface = ''
moninterface = ''
monitor_enable  = 'airmon-ng start '
monitor_disable = 'airmon-ng stop '

max_bytes = 128 # da rivedere si puo accorciare
promiscuous = True
read_timeout = 10
ignore = [] #mac da ignorare (ex. accesspoint della rete)
ha={}

delay = 5 # delay per export
lastexport = datetime.datetime.now()

#scrittura su file
def exporter(haexport):
    name = "wfm "+ str(datetime.datetime.now()) +".log"
    with open(name, "a") as myfile:
        for h in haexport:
            myfile.write(h + "\n")
            for n in haexport.get(h):
                t = n[0]
                i = n[1]
                myfile.write("      " + str(t) + " |> " + str(i) + "\n")

# callback per ricevere pacchetti
def recv_pkts(hdr, data):
    global lastexport
    global ha
    
    try:
        #decodifica del pacchetto
        radio = RadioTapDecoder().decode(data)
        datadown = radio.get_body_as_string()
        ethe = Dot11ControlDecoder().decode(datadown)
        datadowndown = ethe.get_body_as_string()
        decodedDataDownDown = DataDecoder().decode(datadowndown)
        ethMacS = [None] * 6
        for i in range(0,6):
            #salto i primi 8 byte per ottenere il mac trasmittente
            ethMacS[i] = hex(decodedDataDownDown.get_byte(8+i)) 
        macS = ':'.join(map(str, ethMacS))
        s = type(radio.get_dBm_ant_signal())

        time = datetime.datetime.now()

        #aggiunta al dizionario
        if (s is int) & (macS not in ignore):
            signal = hex(radio.get_dBm_ant_signal())
            t = (time,signal)
            if (ha.has_key(macS)):
                ha.get(macS).append(t)
            else:
                l = [t]
                ha[macS] = l

        #esporta su file (thread in parallelo)
        if ((time - lastexport).seconds > delay) & len(ha.keys()) :
            haexport = ha
            ha = {}
            lastexport = time
            thread.start_new_thread(exporter, (haexport, ) )
    
    except KeyboardInterrupt: raise
    except: pass

def mysniff(interface):
    pcapy.findalldevs()
    pc = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)
    pc.setfilter('')    
    packet_limit = -1 # -1 per infiniti
    pc.loop(packet_limit, recv_pkts) # cattura pacchetti

def main():

    global interface
    global moninterface
    global monitor_enable
    global monitor_disable
    global ignore

    interfaces = os.listdir('/sys/class/net/')
    
    if (len(sys.argv) == 2) and (sys.argv[1] in interfaces) or ((len(sys.argv) == 3) and (sys.argv[1] in interfaces) and (os.path.isfile(sys.argv[2]))):
        interface = sys.argv[1]
        moninterface = interface + 'mon'
        monitor_enable = monitor_enable + interface + ';'
        monitor_disable = monitor_disable + moninterface + ';'

        if len(sys.argv) == 3:
            tree = ET.parse(sys.argv[2])
            root = tree.getroot() 

            for child in root:
                ignore.append(child.text)

        os.system(monitor_enable)
        try: mysniff(moninterface)
        except KeyboardInterrupt: sys.exit()
        finally:
            os.system(monitor_disable)
    else:
        print '[!] Insert a valid interface'
        print '[!] example: python ' + sys.argv[0] + ' eth0'
        print '[!] example: python ' + sys.argv[0] + ' eth0 ./ignore.xml'

main()