from utils.talker import Talker
from utils.pipeline import Pipeline
from utils.init_functions import Setup
from utils.grafana_dashboard import DashBoard
from nfstream.streamer import NFStreamer

import logging
import subprocess
import signal
import sys
import tempfile
import os
import datetime
import traceback
import rrdtool
import ipaddress
import operator
import configparser
from concurrent.futures.thread import ThreadPoolExecutor
import multiprocessing
import time

# Formato di display della data
p = '%Y-%m-%d--%H:%M:%S'
pid_child = 0

def producer(pl, chosen_if, rrd_step):
    try:
        print("producer is active")
        p_out,p_in = multiprocessing.Pipe()

        global pid_child
        pid_child = os.fork()

        if (pid_child == 0):#CHILD

            def signal_handler(sig, frame):
                    print('Stopping TcpDump')
                    process.terminate()
                    sys.exit(0)
            signal.signal(signal.SIGINT, signal_handler)

            os.setuid(0)#Always enabled root
            while True:
                pcapfile,path = tempfile.mkstemp(suffix='.pcap')  # creates the file with the umask 600, the owner of the file may read from and write to it
                process = subprocess.Popen(['timeout', rrd_step, 'tcpdump', '-i', chosen_if,'-w', path, '-U'])
                process.wait()
                p_in.send(path)

        else:#FATHER

            while True:

                path = p_out.recv() #Bloking call
                finish_date = datetime.datetime.now()
                pl.set_message(finish_date.timestamp(), path)
            
    except Exception as e:
        print(e)
        traceback.print_exc()


def consumer(pl, rrd_step, ttl, rk_tim, max_top, filter_mode, db, max_talkers):
    try:

        # Define parameters for RRD
        hb = str(int(rrd_step) * 3)
        min_rrd_value = "0"
        max_rrd_value = "U"

        # Structure that will contain all talkers data
        talkers = {}

        # Lists that contain top3 of every metric
        last_sort_in = []
        last_sort_out = []
        last_sort_both = []

        # l'rrd contiene caselle per i dati fino a adesso - step
        creationtimestring = 'now-' + str(int(rrd_step) + 1) + 's'

        # Metadata+StdDev_Stats RRD
        rrdtool.create("./rrd/Statistics.rrd", '--start', creationtimestring,
                       '--step', rrd_step, 'RRA:AVERAGE:0.5:1:1000',
                       'DS:In:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:Out:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:N_Talkers:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:MeanIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:MeanOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:MeanBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:VarianceIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:VarianceOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:VarianceBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:StdDevIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:StdDevOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:StdDevBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:UpperBoundIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:UpperBoundOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:UpperBoundBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value)
                       )

        first_cycle = True
        ntalkers = 0 
        i = 0 #Cycle counter

        while True:

            # ---------------------------------------------------------#
            #          FIRST PHASE: Preparing data from pcap          #
            # ---------------------------------------------------------#

            # Reset Period/Cycle variables
            if first_cycle or i == rk_tim:
                i = 0
                period_in = 0
                period_out = 0
                period_both = 0

                for talker in talkers.values():
                    talker.ResetTotalPeriodCounter()

                first_cycle = False

            cycle_in_sum = 0
            cycle_out_sum = 0
            cycle_both_sum = 0

            # Reconstruct the file name
            ts,f_name= pl.get_message() #Blocking 
            timestring = datetime.datetime.fromtimestamp(ts).strftime(p)
            print("nuovo file generato , aggiorno\n\n\n")

            os.seteuid(0) #Enabling root -> we are reading

            flow_streamer = NFStreamer(source=f_name, statistical_analysis=True, promiscuous_mode=True,
                                       accounting_mode=0)

            flows = list(flow_streamer) #temporary structure to avoid to hold root 
            
            os.remove(f_name)  # Remove temporary file 
            os.seteuid(int(os.environ.get('SUDO_GID'))) #Disabling root


            # Studying flows , if it's a new flow create the structure and rdd o/w update it
            for flow in flows:

                print(flow.application_name + " -> " + flow.src_ip + " -> " + flow.dst_ip + "[" + str(
                    flow.src2dst_bytes) + "] " \
                      + flow.dst_ip + " -> " + flow.src_ip + "[" + str(flow.dst2src_bytes) + "]")

                if ipaddress.ip_address(flow.src_ip).is_private and ipaddress.ip_address(flow.dst_ip).is_private:
                    continue

                if filter_mode == "ip":

                    if ipaddress.ip_address(flow.dst_ip).is_private:
                        curr_talker = talkers.get(flow.src_ip) # try to get the talker associated with the key
                        if curr_talker is None: #if it's None then we have to insert it

                            if( ntalkers < max_talkers):
                                # create talker structure
                                curr_talker = Talker(flow.src_ip, flow.application_name,flow.src2dst_bytes,
                                                    flow.dst2src_bytes, "ip"
                                                    ,flow.application_category_name, flow.application_is_guessed,
                                                    flow.requested_server_name, flow.client_fingerprint,
                                                    flow.server_fingerprint,
                                                    flow.user_agent, flow.content_type)

                                # create his RRD only when talker is first seen
                                curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, ts, creationtimestring)
                                # insert in talkers
                                talkers[flow.src_ip] = curr_talker
                                # new talker
                                ntalkers += 1

                        else:
                            curr_talker.update(ts,flow.src2dst_bytes,flow.dst2src_bytes)

                    else:
                        curr_talker = talkers.get(flow.dst_ip) # try to get the talker associated with the key
                        if curr_talker is None: #if it's None then we have to insert it

                            if( ntalkers < max_talkers):
                                # create talker structure
                                curr_talker = Talker(flow.dst_ip, flow.application_name,flow.dst2src_bytes,
                                                    flow.src2dst_bytes, "ip"
                                                    , flow.application_category_name, flow.application_is_guessed,
                                                    flow.requested_server_name, flow.client_fingerprint,
                                                    flow.server_fingerprint,
                                                    flow.user_agent, flow.content_type)

                                # create his RRD only when talker is first seen
                                curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, ts, creationtimestring)
                                # insert in talkers
                                talkers[flow.dst_ip] = curr_talker
                                # new talker
                                ntalkers += 1
                        else:
                            curr_talker.update(ts,flow.dst2src_bytes,flow.src2dst_bytes)

                ###################################################################################
                elif filter_mode == "prot7":

                    curr_talker = talkers.get(flow.application_name)  # try to get the talker associated with the key
                    if curr_talker is None:  # if it's None then we have to insert it

                        if( ntalkers < max_talkers):

                            if ipaddress.ip_address(flow.dst_ip).is_private:  # flow localhost -> talker
                                # create talker structure
                                curr_talker = Talker(flow.dst_ip, flow.application_name,flow.src2dst_bytes,
                                                    flow.dst2src_bytes, "prot7"
                                                    ,flow.application_category_name, flow.application_is_guessed,
                                                    flow.requested_server_name, flow.client_fingerprint,
                                                    flow.server_fingerprint,
                                                    flow.user_agent, flow.content_type)

                            else:  # flow talker -> localhost
                                # create talker structure
                                curr_talker = Talker(flow.src_ip, flow.application_name, flow.dst2src_bytes,
                                                    flow.src2dst_bytes, "prot7"
                                                    , flow.application_category_name, flow.application_is_guessed,
                                                    flow.requested_server_name, flow.client_fingerprint,
                                                    flow.server_fingerprint,
                                                    flow.user_agent, flow.content_type)

                            # create his RRD only when talker is first seen
                            curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, ts, creationtimestring)
                            # insert in talkers
                            talkers[flow.application_name] = curr_talker
                            # new talker
                            ntalkers += 1

                    else:
                        if ipaddress.ip_address(flow.dst_ip).is_private:
                            curr_talker.update(ts, flow.src2dst_bytes, flow.dst2src_bytes)
                        else:
                            curr_talker.update(ts, flow.dst2src_bytes, flow.src2dst_bytes)

                else:
                    exit(-1)



            # -------------------------------------------------------------------#
            #     SECOND PHASE: Aggregate flows data and removing old flows      #
            # -------------------------------------------------------------------#

            # Removing old flows / update the rest
            for talker in list(talkers.values()):

                # If flow has not been updated in the last ttl seconds , remove it
                if talker.lastupdate + ttl <= ts:

                    if filter_mode == "ip":
                        curr = talkers.pop(talker.ip)

                    elif filter_mode == "prot7":
                        curr = talkers.pop(talker.prot7)

                    # Case 1 : the flow is new -> talker.x - talker.x_current = 0 and period has no data of talker

                    # Case 2 : the flow is not new -> talker.x - talker.x_current
                    #                             -> (i-1 talker.x_current sum) = talker.x - last talker.x_current [Y]
                    #                             -> period has inside last i-1 cycle sum , so lets clean data from removed talker by subtracting Y

                    period_in -= talker.in_bytes - talker.in_bytes_current
                    period_out -= talker.out_bytes - talker.out_bytes_current
                    period_both -= talker.inandout_bytes - talker.inandout_bytes_current
                    ntalkers -= 1

                    curr.RRDdeletion()

                # o/w consider it for the std_dev calculation
                else:
                    #we sum all the bytes in/out/both from all the talkers
                    cycle_in_sum += talker.in_bytes_current
                    cycle_out_sum += talker.out_bytes_current
                    cycle_both_sum += talker.inandout_bytes_current
                    talker.RRDupdate(ts)

            # we calculate mean,variance and stdev not only on the current bytes in/out
            # but on the summation of the bytes of a period(RRD_Step*Ranking Refresh Time)
            period_in += cycle_in_sum
            period_out += cycle_out_sum
            period_both += cycle_both_sum

            # Check if data is enough
            if ntalkers > 0 and len(talkers) > 0:

                # -------------------------------------------------------------------#
                #             THIRD PHASE: Standard Dev Calculating                 #
                # -------------------------------------------------------------------#

                # Calculating the mean of the bytes in/out/both for the current period
                mean_in = period_in / ntalkers
                mean_out = period_out / ntalkers
                mean_both = period_both / ntalkers

                # Calculating variance of every metric
                variance_in = 0
                variance_out = 0
                variance_both = 0

                for talker in talkers.values():
                    # Calculating the variance of every metric for the current period
                    # taking the sum of the in/out/both bytes in this period of a single talker in this period
                    # variance is the square of the difference beetween each point and the mean
                    variance_in += pow(talker.in_bytes - mean_in, 2)
                    variance_out += pow(talker.out_bytes - mean_out, 2)
                    variance_both += pow(talker.inandout_bytes - mean_both, 2)

                    # Update total counter and reset current
                    talker.ResetCurrentCounter()

                    # Little dump to read data manualy and check
                    if filter_mode == "ip":
                        rrdtool.dump("./rrd/RRD_" + talker.ip + ".rrd",
                                     "./xml/" + talker.ip + ".xml")

                    elif filter_mode == "prot7":
                        rrdtool.dump("./rrd/RRD_" + talker.prot7 + ".rrd",
                                     "./xml/" + talker.prot7 + ".xml")

                # Calculating Standard Deviation of every metric
                # stdev is the square root of variance/number of terms
                stdev_in = pow(variance_in / ntalkers, 1 / 2)
                stdev_out = pow(variance_out / ntalkers, 1 / 2)
                stdev_both = pow(variance_both / ntalkers, 1 / 2)
            else:
                mean_in = mean_out = mean_both = variance_in = variance_out = variance_both = stdev_in = stdev_out = stdev_both = int(0)
            

            # -------------------------------------------------------------------#
            #            FOURTH PHASE: Updating RRD and GRAFANA                 #
            # -------------------------------------------------------------------#

            upperbound_in = mean_in + stdev_in
            upperbound_out = mean_out + stdev_out
            upperbound_both = mean_both + stdev_both

            lowerbound_in = mean_in - stdev_in
            if lowerbound_in < 0: lowerbound_in = 0

            lowerbound_out = mean_out - stdev_out
            if lowerbound_out < 0: lowerbound_out = 0

            lowerbound_both = mean_both - stdev_both
            if lowerbound_both < 0: lowerbound_both = 0

            rrdtool.update("./rrd/Statistics.rrd",
                           f'{ts}' + ':' + str(period_in) + ':' + str(period_out) + ':' + str(ntalkers) + ':'
                           + str(mean_in) + ':' + str(mean_out) + ':' + str(mean_both) + ':'
                           + str(variance_in) + ':' + str(variance_out) + ':' + str(variance_both) + ':'
                           + str(stdev_in) + ':' + str(stdev_out) + ':' + str(stdev_both) + ':'
                           + str(upperbound_in) + ':' + str(lowerbound_in) + ":"
                           + str(upperbound_out) + ':' + str(lowerbound_out) + ":"
                           + str(upperbound_both) + ':' + str(lowerbound_both))

            if len(talkers) > 0:

                change = False

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('in_bytes'), reverse=True)

                if last_sort_in != t_sorted:
                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topin(strings[:max_top])
                    last_sort_in = t_sorted
                    change = True

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('out_bytes'), reverse=True)

                if last_sort_out != t_sorted:

                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topout(strings[:max_top])
                    last_sort_out = t_sorted
                    change = True

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('inandout_bytes'), reverse=True)

                if last_sort_both != t_sorted:

                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topboth(strings[:max_top])
                    last_sort_both = t_sorted
                    change = True

                if change is True:
                    db.upload_json(talkers)
                i += 1

    except Exception as e:
        print(e)
        traceback.print_exc()


def signal_handler(sig, frame):
        print(os.getpid())
        # close the grafana started from python by closing his port
        os.system("sudo fuser -k 9000/tcp")
        # remove ->':' from overrides
        db.program_exit_update()
        sys.exit(0)


if __name__ == '__main__':

    os.seteuid(int(os.environ.get('SUDO_GID'))) #start as non-root

    Setup()

    # Get settings from config.ini
    conf = configparser.ConfigParser()
    conf.read("config.ini")
    interface = conf.get("Settings", "interface")
    grafana_api = conf.get("Settings", "grafana_api")
    filter_mode = conf.get("Settings", "filter_mode")
    rrd_step = conf.get("Settings", "refresh")
    ttl = conf.get("Settings", "ttl_flow")
    max_talkers = conf.get("Settings", "max_talkers")
    rk_tim = conf.get("Settings", "refr_ranking")
    max_top = conf.get("Settings", "max_top")

    print("Do you want me to start grafana-rrd-server plugin?")

    while(True):
        answer = input("[y/n] ")
        if answer == "y":
            #Close any process that it's using port 9000
            os.system("sudo fuser -k 9000/tcp")
            stddirpath = (os.path.expanduser("~") + "/go/bin/grafana-rrd-server")
            localpath = "./grafana-rrd-server"

            #Starting Simple_Json RRD
            if os.path.exists(stddirpath):
                os.system("sudo " + stddirpath + " -r ./rrd -s  " + rrd_step + " &")
            elif os.path.exists(localpath):
                os.system("sudo " + localpath + " -r ./rrd -s " + rrd_step + " &")
            else:
                print("Cant find grafana-rrd-server -- Be sure to start grafana-rrd-server by yourself")
            break

        elif answer == "n":
            print("Be sure to start grafana-rrd-server by yourself")
            break
        else:
            print("incorrect choice")

    db = DashBoard(grafana_api, rrd_step, answer == 'y')
    
    #Register signal to handle
    def signal_handler(sig, frame):
        print('Stopping application')
        if answer == 'y':
            #close the grafana started from python by closing his port
            os.seteuid(0)  # need to be root to stop pcap capture and terminate child process
            os.system("sudo fuser -k 9000/tcp")
            #Close tcpdump subprocess
            os.kill(pid_child,signal.SIGINT)
            # remove ->':' from overrides
            db.program_exit_update()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start software
    executor = ThreadPoolExecutor(max_workers=2)
    pl = Pipeline()
    executor.submit(producer, pl, interface, rrd_step)
    executor.submit(consumer, pl, rrd_step, int(ttl), int(rk_tim), int(max_top), filter_mode, db, int(max_talkers))