#!/usr/bin/env python3

"""Traffic flow is the netflow implementation by Mikrotik, 
this program collect this data and expose a Web API for InfluxDB

@autor: Alessandro Ambrogini

    Prerequisites
        python3
        python netflow library (https://pypi.org/project/netflow/)
        python netaddr library (https://pypi.org/project/netaddr/)
        python flask library   (https://flask.palletsprojects.com/en/1.1.x/)
    Run
        make the file executable
            chmod +x trafficflow_collector.py

        ./trafficflow_collector.py
"""
import sys
import modules.config as config
import netflow
import socket
from netflow.v9 import V9TemplateNotRecognized
from netaddr import IPNetwork, IPAddress
import modules.rest_api as api

#definizione template iniziale
templates = {"netflow": {}}

#definisco la sequenza attesa del pacchetto netflow per evitare di 
# collezionare gli stessi dati più volte e per segnalare 
# eventuali pacchetti persi
flow_sequence_exp = 0

#definisco una variabile che mi contenga il sysUpTime del mio router
sysUpTime = 0

#definizione del socket in attesa su porta 2055
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 2055))
try:
    #inizializzo la REST API
    api.run_rest_api()
    #ciclo infinito, raccolgo i dati provenienti dal router
    while True:
        payload, client = sock.recvfrom(4096)
        try:
            # il template viene passato per riferimento al parser, 
            # viene aggiornato da quest'ultimo quando il pacchetto lo definisce
            p = netflow.parse_packet(payload, templates)
            if(p.header.version != 9):
                print ("Attivare la versione 9 di traffic flow su router")
                sys.exit()
            
            if(flow_sequence_exp == 0):
                flow_sequence_exp = p.header.sequence
            
            if(sysUpTime == 0):
                sysUpTime = p.header.uptime

            #Se il numero di sequenza del pacchetto è minore di quello atteso
            # è possibile sia un resend del pacchetto e lo scarto.
            #Tuttavia si deve controllare il sysUpTime perchè nel caso il mio
            # router si sia riavviato io non devo scartare alcun pacchetto.
            #Nel caso invece che il sysUpTime non sia minore dell'ultima 
            # rilevazione allora controllo quanto sia lo scarto tra i
            # valori di sequenza, il contatore di sequenza del router 
            # potrebbe essere andato in overflow
            if(p.header.sequence < flow_sequence_exp):
                if(p.header.uptime < sysUpTime):
                    sysUpTime = p.header.uptime
                    flow_sequence_exp = p.header.sequence
                elif(flow_sequence_exp - p.header.sequence > 10):
                    flow_sequence_exp = p.header.sequence
                    

            if(p.header.sequence >= flow_sequence_exp):
                #È possibile incorrere in una sequenza maggiore che potrebbe 
                # identificare un pacchetto perso
                if(p.header.sequence > flow_sequence_exp):
                    print ("Sequenza pacchetto inattesa, possibile perdita")
                    flow_sequence_exp = p.header.sequence
                
                for f in p.flows:
                    #seleziono l'ip locale del flusso
                    ipSrc = IPAddress(f.IPV4_SRC_ADDR)
                    ipDst = IPAddress(f.IPV4_DST_ADDR)
                    ip = ""
                    request_flow = ""
                    if(ipSrc in config.localNet):
                        ip = f.IPV4_SRC_ADDR
                        request_flow = "OUT"
                    #se è un flusso su rete locale ip locale = ip sorgente 
                    # se invece è una richiesta al mio ip pubblico
                    # lo contabilizzo
                    if((ipDst in config.localNet and not request_flow) \
                        or ipDst == config.myPublicIP):
                        ip = f.IPV4_DST_ADDR
                        request_flow = "IN"
                    if(ip != ""):
                        #inserisco i dati nel dizionario
                        nbytes = f.IN_BYTES
                        npackets = f.IN_PKTS
                        k = f.IPV4_SRC_ADDR \
                            + f.IPV4_DST_ADDR \
                            + str(f.L4_SRC_PORT) \
                            + str(f.L4_DST_PORT) \
                            + str(f.PROTOCOL)
                        if(k in config.data):
                            nbytes += config.data[k]['bytes']
                            npackets += config.data[k]['packets']
                        config.data[k] = {
                            'local_ip': ip,
                            'request_flow': request_flow,
                            'src_ip': f.IPV4_SRC_ADDR,
                            'dst_ip': f.IPV4_DST_ADDR,
                            'bytes': nbytes,
                            'packets': npackets,
                            'src_port': f.L4_SRC_PORT,
                            'dst_port': f.L4_DST_PORT,
                            'timestamp': p.header.timestamp,
                            'protocol': f.PROTOCOL
                        }
                flow_sequence_exp += 1
        except (V9TemplateNotRecognized):
            print ("Decodifica fallita, in attesa del pacchetto " +
                "di definizione del template")
except KeyboardInterrupt:
    print("\nCollettore terminato")
    pass