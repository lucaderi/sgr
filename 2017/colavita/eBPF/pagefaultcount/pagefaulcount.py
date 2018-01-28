#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF, PerfType , PerfSWConfig
import ctypes as ct
import signal
from time import sleep

def signal_ignore(signum,frame):
    print()
# load BPF program
b = BPF(src_file="source.c")
b.attach_perf_event(
    ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.PAGE_FAULTS_MAJ,
    fn_name="page_maj_flt",sample_period=0,sample_freq=49)
b.attach_perf_event(
    ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.PAGE_FAULTS_MIN,
    fn_name="page_min_flt",sample_period=0,sample_freq=49)

print("Running for {} seconds or hit Ctrl-C to end.".format(100))

try:
    sleep(float(100))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
    print(" ")

TASK_COMM_LEN = 16    # linux/sched.h
min_flt_count = {}
for (k, v) in b.get_table('min_flt_table').items():
    min_flt_count[(k.pid, k.cpu, k.comm)] = v.value

maj_flt_count = {}
for (k,v) in b.get_table('maj_flt_table').items():
    maj_flt_count[(k.pid , k.cpu , k.comm)] = v.value

print('{:<8s} {:<20s} {:<12s} {:<12s} {:<12s}'.format("PID","NAME","CPU","MIN_FLT","MAX_FLT"))

for (k, v) in sorted(b.get_table('min_flt_table').items(), key= lambda (k,v): v.value,reverse=True): 
    try:
        maj_miss = maj_flt_count[(k.pid, k.cpu, k.comm)]
    except KeyError:
        maj_miss = 0
    print('{:<8d} {:<20s} {:<12d} {:<12d} {:<12d}'.format(
        k.pid, k.comm.decode(), k.cpu, v.value, maj_miss))    
    
for (k, v) in sorted(b.get_table('maj_flt_table').items(), key= lambda (k,v): v.value,reverse=True):
    repeat = 1
    try:
        min_miss = min_flt_count[(k.pid, k.cpu, k.comm)]
    except KeyError:
        min_miss = 0
        repeat = 0
    if not repeat:
        print('{:<8d} {:<20s} {:<12d} {:<12d} {:<12d}'.format(
            k.pid, k.comm.decode(), k.cpu, min_miss, v.value))
