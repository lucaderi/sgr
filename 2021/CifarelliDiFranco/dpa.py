#!/usr/bin/python3

import pyshark
import utils
import sys

def main():
    dns_query_packets = {}  #hashtable contenente pacchetti di query DNS pervenute
    dns_query_na = {}       #lista contenente pacchetti di query DNS non pervenute
    dns_resp_packets = {}   #hashtable contenente pacchetti di risposte DNS pervenute
    dns_resp_na = {}        #lista contenente pacchetti di risposte DNS non pervenute
    cap = pyshark.FileCapture(sys.argv[1])
    p = cap.next()
    while True:
        try:
            if(int(p.dns.flags_response) == 1):
                utils.check_dns_rcode(p.dns.flags_rcode, p.number)
                if(p.dns.id in dns_resp_packets.keys()):
                    if p.dns.id not in dns_resp_na.keys(): dns_resp_na[p.dns.id] = ""
                    dns_resp_na[p.dns.id] += dns_resp_packets[p.dns.id]+" "
                    dns_resp_packets[p.dns.id] = p.number
                else:
                    dns_resp_packets[p.dns.id] = p.number
            else:
                if(p.dns.id in dns_query_packets.keys()):
                    if p.dns.id not in dns_query_na.keys(): dns_query_na[p.dns.id] = ""
                    dns_query_na[p.dns.id] += dns_query_packets[p.dns.id]+" "
                    dns_query_packets[p.dns.id] = p.number
                else:
                    dns_query_packets[p.dns.id] = p.number
            p = cap.next()
        except StopIteration:
            break
    
    utils.print_dns_analysis(dns_query_packets, dns_resp_packets, dns_query_na, dns_resp_na)
    utils.print_dns_rcodes()

if __name__ == "__main__":
    main()