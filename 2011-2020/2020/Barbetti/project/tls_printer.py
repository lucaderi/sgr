#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from nfstream import NFStreamer
import os.path
import operator
import sys
import socket


#file containing top 1000 most visited sites
FILENAME="top10k.txt"

def print_tls_flows(tls_dict,total_packets):
    print()
    print("****************************** TLS STATS ******************************")
    print()
    for key,value in tls_dict.items():
        pkt_count=get_pkt_count(value)
        p = round((pkt_count*100)/total_packets,2)
        print(f'Host {key} generated {pkt_count}({p}%) packets.')
        #******
        #Analyze TLS traffic
        tls_known , tls_unknown = split_by_app_name(value)
        detect_tls_traffic(tls_unknown)
        #merge 'TLS.Unknown' traffic
        merged = merge_same_tls(tls_known+tls_unknown)
        tls_flows = merged
        #sort flows lexicographically by application name
        tls_flows.sort(key=myfunc)
        #
        l=build_flow_perc_list(tls_flows,pkt_count)
        #*******
        i=0
        for flow,perc in l:
            i=i+1
            if not flow.requested_server_name:
                print(f'{i})        {perc}%  --  {flow.application_name}  --  {flow.src_ip}  --  {flow.dst_ip}')
                continue
            if socket.gethostbyname(flow.requested_server_name) != "127.0.0.1" :
                print(f'{i})        {perc}%  --  {flow.application_name}  --  {flow.src_ip}  --  {flow.dst_ip}  --  {flow.requested_server_name}  --  SNI authenticated')
            else:
                print(f'{i})        {perc}%  --  {flow.application_name}  --  {flow.src_ip}  --  {flow.dst_ip}  --  {flow.requested_server_name}  --  WARNING:non-existing SNI ')


def build_flow_perc_list(flows,pkts):
    #return a list, each entry is : 
    #   a flow and its percentace of packets generated 
    l=[]
    for flow in flows:
        perc=round((flow.bidirectional_packets*100)/pkts,2)
        l.append((flow,perc))
    l.sort(key=operator.itemgetter(1),reverse=True)
    return l


def detect_tls_traffic(flows):
    if flows is None:
        return
    for flow in flows:
        #retrieve informations about flows[i] 
        server_name_raw=flow.requested_server_name
        l=server_name_raw.split('.')
        if(len(l)>1):
            server_name=l[-2]
        else:
            server_name=server_name_raw
        if "." not in flow.application_name:
            if grep(server_name):
                flow.application_name="TLS."+server_name
            else :
                flow.application_name="TLS.Unknown"

def grep(s_name):
    # boolean for grep s_name $FILENAME
    if(s_name == ""):
        return False
    with open(FILENAME) as f :
        for line in f:
            if s_name in line:
                f.close()
                return True
        f.close()
        return False

def get_pkt_count(flows):
    x = 0
    for flow in flows:
        x += flow.bidirectional_packets
    return x

def split_by_app_name(tls_flows):
    #split a flow list into two flow lists: one with the flows with traffic that has been recognized from nDPI(e.g TLS.Facebook), and the other with the flows that hasn't been recognized 
    known=[]
    unknown=[]
    for flow in tls_flows:
        if "." in flow.application_name:
            known.append(flow)
        else :
            unknown.append(flow)
    return known,unknown

def sort_(flows):
    #sort a list of flows ; put the TLS.Unknown traffic at the end
    tls_unknown=[]
    tls_known=[]
    for flow in flows:
        if "TLS.Unknown" in flow.application_name:
            tls_unknown.append(flow)
        else :
            tls_known.append(flow)
    sorted_flows=tls_known + tls_unknown
    return sorted_flows

#used to sort a flow list by application_name
def myfunc(e):
    return e.application_name

def merge_same_tls(flows):
    #Merge the same TLS.Unknown flows
    unknown=[]
    known=[]
    for flow in flows:
        if "TLS.Unknown" in flow.application_name:
            unknown.append(flow)
        else:
            known.append(flow)
    tmp=[]
    boolean=False
    for flowU in unknown:
        if not tmp:
            tmp.append(flowU)
        else :
            for flowT in tmp:
                if(flowU.requested_server_name==flowT.requested_server_name and
                        flowU.src_ip==flowT.src_ip and
                        flowU.dst_ip==flowT.dst_ip ):
                    flowT.bidirectional_packets+=flowU.bidirectional_packets
                    flowT.bidirectional_bytes+=flowU.bidirectional_bytes
                    flowT.src2dst_packets+=flowU.src2dst_packets
                    flowT.src2dst_bytes+=flowU.src2dst_bytes
                    flowT.dst2src_packets+=flowU.dst2src_packets
                    flowT.dst2src_bytes+=flowU.dst2src_bytes
                    boolean=True
                    break
            if(boolean is False):
                tmp.append(flowU)
            boolean=False
    #now merge known
    tmp2=[]
    boolean=False
    for flow in known:
        if not tmp2:
            tmp2.append(flow)
        else:
            for flowT in tmp2:
                if(flow.requested_server_name==flowT.requested_server_name and
                        flow.src_ip==flowT.src_ip and
                        flow.dst_ip==flowT.dst_ip ):
                    flowT.bidirectional_packets+=flow.bidirectional_packets
                    flowT.bidirectional_bytes+=flow.bidirectional_bytes
                    flowT.src2dst_packets+=flow.src2dst_packets
                    flowT.src2dst_bytes+=flow.src2dst_bytes
                    flowT.dst2src_packets+=flow.dst2src_packets
                    flowT.dst2src_bytes+=flow.dst2src_bytes
                    boolean=True
                    break
            if(boolean is False):
                tmp2.append(flow)
            boolean=False
    l = tmp2+tmp
    return l

def get_proto_distribution(streamer):
    #return a dictionary of list ; each key is a src_ip inside the pcap and the value is the TLS flow list it generated
    dic={}
    tls_dict={}
    total_pkt=0
    for flow in streamer:
        total_pkt+=flow.bidirectional_packets
        if str(flow.src_ip) in dic:
            dic[str(flow.src_ip)].append(flow)
        else :
            dic[str(flow.src_ip)]=[]
            dic[str(flow.src_ip)].append(flow)
        if "TLS" in flow.application_name :
            if str(flow.src_ip) in tls_dict:
                tls_dict[str(flow.src_ip)].append(flow)
            else:
                tls_dict[str(flow.src_ip)]=[]
                tls_dict[str(flow.src_ip)].append(flow)
    for key,value in dic.items():
        #key=IP who generated traffic
        #value=list of flows generated by key
        #
        #for each ip inside dict, analyze its traffic: 
        #   collect application protocols distribution (DNS X%, HTTP Y%, TLS Z%) -> need to merge 
        #   return a tls_dict for further print more in depth stats about TLS
        pkt_count=get_pkt_count(value)
        perc=round((pkt_count*100)/total_pkt,2)
        tmp={}
        tls_flows=[]
        for flow in value:
            #if its tls save it;
            #save the amount of packets for each protocol
            if "TLS" in flow.application_name:
                tls_flows.append(flow)
            stripped=flow.application_name.split('.')[0]
            if stripped in tmp:
                tmp[stripped]+=flow.bidirectional_packets
            else:
                tmp[stripped]=0
                tmp[stripped]+=flow.bidirectional_packets
        print(f'Host -> {key} generated {pkt_count}({perc}%) packets:')
        for key1,value1 in tmp.items():
            perc1=round((value1*100)/pkt_count,2)
            print(f'             Protocol -> {key1} -> {value1}({perc1}%) packets.')
    return tls_dict


if __name__ == "__main__":
    path = sys.argv[1]
    if ".pcap" not in path:
        print(path + " not a .pcap file, exiting")
        sys.exit()
    if not os.path.isfile(FILENAME):
        print(FILENAME+" not found, exiting")
        sys.exit()
    flow_streamer = NFStreamer(source=path, statistical_analysis=True)
    total_packets = 0
    try:
        for flow in flow_streamer:
            try:
                total_packets += flow.bidirectional_packets
            except KeyError:
                total_packets += flow.bidirectional_packets
        print(str(total_packets) + " total packets")
        #
        #print the protocol distribution by ip and get a dictionary containing every tls flow generated by each ip
        tls_dict = get_proto_distribution(flow_streamer)
        print_tls_flows(tls_dict,total_packets)
    except KeyboardInterrupt:
        tls_flows = get_proto_distribution(flow_streamer)
        print_tls_flows(tls_flows)
        print("Terminated.")

