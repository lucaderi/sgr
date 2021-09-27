#!/usr/bin/python3

import subprocess
import time
import threading
from influxdb import InfluxDBClient
import utils
import pyshark
import os
import signal
import shutil
import datetime
import numpy
import traceback

args = utils.create_parser()

IP_resps = {}
values = {}

def shutdown(snifferpid):
    while True:
        user_input = input("type quit (only) when the capture has to arrest\n")
        if user_input == "quit":
            os.kill(snifferpid, signal.SIGINT)
            break
        else: continue

def main():
    if not os.path.isdir(utils.PCAP_PATH): os.mkdir(utils.PCAP_PATH)
    if not os.path.isdir(utils.LIVECAPTURE_PATH): os.mkdir(utils.LIVECAPTURE_PATH)
    if not os.path.isdir(utils.MERGED_PATH): os.mkdir(utils.MERGED_PATH)
    if not os.path.isdir(utils.OUTPUT_PATH): os.mkdir(utils.OUTPUT_PATH)
    if not os.path.isdir(utils.DEBUG_PATH): os.mkdir(utils.DEBUG_PATH)

    if args.postanalysis and not args.report:
        print("it's not possible to do a post analysis without creating a report (flag -pa set but flag -r not set)")
        return

    influx_client = InfluxDBClient(username="students", password="gr21", database="progettogr")

    ipv4, subnet = utils.get_net_info(args.interface)
    print("sniffing on "+args.interface+" (IPv4 = "+ipv4+", subnet = "+subnet+")")

    if not args.ignore:
        print("WARNING: -ign (--ignore) flag is not set: dns traffic addressed to this machine will be counted and may cause significant slowdowns during Tshark analysis")
        with open(utils.DEBUG_PATH+"/dcaperr.txt", "w") as dcaperr: proc = subprocess.Popen(["tshark", "-i"+args.interface, "-fudp port 53 and dst net "+subnet, "-bduration:10", "-w"+utils.LIVECAPTURE_PATH+"/dcapout.pcapng"], stderr=dcaperr)
    else:
        with open(utils.DEBUG_PATH+"/dcaperr.txt", "w") as dcaperr: proc = subprocess.Popen(["tshark", "-i"+args.interface, "-fudp port 53 and dst net "+subnet+" and not dst "+ipv4, "-bduration:10", "-w"+utils.LIVECAPTURE_PATH+"/dcapcallout.pcapng"], stderr=dcaperr)
    snifferpid = proc.pid

    shutdown_thread = threading.Thread(target=shutdown, args=(snifferpid, ))
    shutdown_thread.start()

    try: 
        if args.report: analysis_1(influx_client, shutdown_thread)
        else: analysis_2(influx_client, shutdown_thread)
    except Exception:
        traceback.print_exc()
        clear()
        os.kill(snifferpid, signal.SIGINT)
        return

    if args.report:
        (fpath, date, clock) = merge()
        if args.postanalysis:
            with open(utils.OUTPUT_PATH+"/pcapanalysis"+date+clock+".txt", "w") as pcap_analysis: subprocess.call(["python3", utils.SRC_PATH+"/dpa.py", fpath+".pcapng"], stdout=pcap_analysis)
    else: clear()

def analysis_1(influx_client, shutdown_thread): #if flag -r is set
        while len(os.listdir(utils.LIVECAPTURE_PATH)) <= 2 and shutdown_thread.is_alive(): time.sleep(0.1)
        while not len(os.listdir(utils.LIVECAPTURE_PATH)) == 0:
            time_1 = time.monotonic()
            dir = os.listdir(utils.LIVECAPTURE_PATH)
            f = sorted(dir)[0]
            fpath = utils.LIVECAPTURE_PATH+"/"+f
            capture = pyshark.FileCapture(input_file=fpath)
            capture.apply_on_packets(process_packet)
            insert_values(args.sample)
            threshold, alert = get_threshold(args.sample)
            influx_write(influx_client, threshold, alert)
            shutil.move(fpath, utils.PCAP_PATH+"/"+f)
            capture.clear()
            time_2 = time.monotonic()
            #print(time_2 - time_1)
            time.sleep(10.0 - (time_2 - time_1))

def analysis_2(influx_client, shutdown_thread): #if flag -r is not set
        while len(os.listdir(utils.LIVECAPTURE_PATH)) <= 1 and shutdown_thread.is_alive(): time.sleep(1)
        while not len(os.listdir(utils.LIVECAPTURE_PATH)) == 0:
            time_1 = time.monotonic()
            dir = os.listdir(utils.LIVECAPTURE_PATH)
            f = sorted(dir)[0]
            fpath = utils.LIVECAPTURE_PATH+"/"+f
            capture = pyshark.FileCapture(input_file=fpath)
            capture.apply_on_packets(process_packet)
            insert_values(args.sample)
            threshold, alert = get_threshold(args.sample)
            influx_write(influx_client, threshold, alert)
            os.remove(fpath)
            capture.clear()
            time_2 = time.monotonic()
            #print(time_2 - time_1)
            time.sleep(10.0 - (time_2 - time_1))

def influx_write(influx_client, threshold, alert):
    timestamp = datetime.datetime.now()
    #(threshold, nrec) = utils.get_threshold(influx_client, len(IP_resps.keys()))
    for key in IP_resps.keys():
        if not alert: body = utils.define_point_body(timestamp, 0, key, threshold, IP_resps[key])
        else:
            if IP_resps[key] > threshold: body = utils.define_point_body(timestamp, 1, key, threshold, IP_resps[key])
            else: body = utils.define_point_body(timestamp, 0, key, threshold, IP_resps[key])
        IP_resps[key] = 0
        influx_client.write_points(body)

def process_packet(packet):
    IP_respskeys = IP_resps.keys()
    curr_ip = str(packet.ip.dst)
    if int(packet.dns.flags_rcode) != 0:
        if curr_ip not in IP_respskeys: IP_resps[curr_ip] = 1
        else: IP_resps[curr_ip] = IP_resps[curr_ip] + 1
    else:
        if curr_ip not in IP_respskeys: IP_resps[curr_ip] = 0

def merge():
    pcaps = ""
    pcapdir = os.listdir(utils.PCAP_PATH)
    for f in pcapdir: pcaps = pcaps+utils.PCAP_PATH+"/"+f+" "
    pcaps = pcaps[:len(pcaps) - 1]
    date = str(datetime.datetime.now().date())
    clock = str(datetime.datetime.now().time())[:5]
    fpath = utils.MERGED_PATH+"/dcapout"+date+clock
    os.system("mergecap "+pcaps+" -w "+fpath+".pcapng")
    for f in pcapdir:
        file = utils.PCAP_PATH+"/"+f
        if not os.path.isdir(file): os.remove(file)
    return (fpath, date, clock)

def clear():
    livecapdir = os.listdir(utils.LIVECAPTURE_PATH)
    for f in livecapdir: os.remove(utils.LIVECAPTURE_PATH+"/"+f)
    pcapdir = os.listdir(utils.PCAP_PATH)
    for f in pcapdir: os.remove(utils.PCAP_PATH+"/"+f)    

def insert_values(sample):
    global values

    for key in IP_resps.keys():
        if key not in values.keys():
            values[key] = []
            values[key].insert(0, 0)
        try: values[key].pop(values[key][0]+1)
        except IndexError: pass
        values[key].insert(values[key][0]+1, IP_resps[key])
        values[key][0] = (values[key][0]+1)%sample

def get_threshold(sample):
    global values

    alert = False
    list = []
    for key in values: list = list + values[key][1:]
    print(list)
    if len(list) > 0:
        mean = numpy.round(numpy.mean(list), 3)
        stddev = numpy.round(numpy.std(list, ddof=1), 3)
        if len(list) == sample*len(IP_resps.keys()): alert = True
        return float(mean + stddev), alert
    else: return 0.0, False

if __name__ == "__main__":
    main()
