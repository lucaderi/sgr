#!/usr/bin/python
# encoding=utf8
# autore: Salvatore Costantino
# mail: s.costantino5@studenti.unipi
# fonti
    # https://github.com/iovisor/bcc/blob/master/tools/tcpaccept.py
    # https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6, error
from struct import pack, error as er
import ctypes as ct
from SimpleFlowTable import *
import signal
import sys
import BPFCode
from myParser import *
from Filter import *

# event data
TASK_COMM_LEN = 16      # linux/sched.h

#struttura per conservare dati che arrivano dal kernel(IPv4)
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("port", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

#struttura per conservare dati che arrivano dal kernel(IPv6)
class Data_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("port", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

TABLE_DIM=43 #dimensione tabella hash
cTable=SimpleFlowTable(TABLE_DIM) #tabella hash flussi TCP connect()
aTable=SimpleFlowTable(TABLE_DIM) #tabella hash dei flussi TCP accept()


# process event
def print_ipv4_c_event(cpu, data, size):
    """
        callback per TCP connect() (IPv4)
    """
    try:
        event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
        cTable.insert(event.pid,event.task.decode(),event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)),
            inet_ntop(AF_INET, pack("I", event.daddr)),event.port)
    except (UnicodeDecodeError,ValueError,error,TypeError,er): 
        return

def print_ipv6_c_event(cpu, data, size):
    """
        callback per TCP connect() (IPv6)
    """
    try:
        event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
        cTable.insert(event.pid,event.task.decode(),event.ip,
            inet_ntop(AF_INET6, event.saddr),
            inet_ntop(AF_INET6, event.daddr),event.port)
    except (UnicodeDecodeError,ValueError,error,TypeError): 
        return

def print_ipv4_a_event(cpu, data, size):
    """
        callback per TCP accept() (IPv4)
    """
    try:
        event = ct.cast(data, ct.POINTER(Data_ipv4)).contents 
        aTable.insert(event.pid,event.task.decode(),event.ip,
            inet_ntop(AF_INET, pack("I", event.daddr)),
            inet_ntop(AF_INET, pack("I", event.saddr)),event.port)
    except (UnicodeDecodeError, ValueError,error,TypeError,er):
        return

def print_ipv6_a_event(cpu, data, size):
    """
         callback per TCP accept() (IPv6)
    """
    try:
        event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
        aTable.insert(event.pid,event.task.decode(),event.ip,
            inet_ntop(AF_INET6, event.daddr),
            inet_ntop(AF_INET6, event.saddr),event.port)
    except (UnicodeDecodeError,ValueError,error,TypeError):
        return

flag=True #segnalazione SIGINT

def signal_handler(signal, frame):
    """
        gestore SIGINT
    """
    global flag
    flag=False


def main():
    """
        funzione principale
    """

    args=parseArg() #parsing linea di comando

    bpf_text = BPFCode.text  #definizione codice BPF

    bpf_text=filter(args,bpf_text) #filtraggio in codice BPF

    # initialize BPF
    b = BPF(text=bpf_text)

    #associo funzione <fn_name> a chiamata del kernel <event> (in modo che <fn_name> venga chiamata quando occore <event>) 
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")


    # apertura buffer circolare per comunicazioni kernel->user-space (per i vari "eventi" da monitorare)
    # ed associazione callback
    b["ipv4_connect_events"].open_perf_buffer(print_ipv4_c_event)
    b["ipv6_connect_events"].open_perf_buffer(print_ipv6_c_event)
    b["ipv4_accept_events"].open_perf_buffer(print_ipv4_a_event)
    b["ipv6_accept_events"].open_perf_buffer(print_ipv6_a_event)
    
    signal.signal(signal.SIGINT, signal_handler) #installo signal handler

    print("working... Press CTRL-C to print results")
    while flag==True: #fin tanto che non ricevo SIGINT
        b.kprobe_poll() # polls from all open perf ring buffers 

    f=None
    if args.file: # se scrittura su file 
        try:
            f=open(args.file,'w')

            # lavoro sui descrittori
            out=sys.stdout
            sys.stdout=f
        except IOError:
            print("\nimpossibile scrivere il file specificato: %s" % args.file)
        

    print("\n%-6s %-16.16s %-2s %-39s %-39s %-6s %-5s %s" % ("PID","COMM","IP", "SADDR",
        "DADDR", "RPORT","COUNT","MTBS(s)"))
    cTable.readTable() 

    print("\n%-6s %-16.16s %-2s %-39s %-39s %-6s %-5s %s" % ("PID","COMM","IP", "SADDR",
        "DADDR", "LPORT","COUNT","MTBS(s)"))
    aTable.readTable()
    
    if f!=None:
        f.close()
        sys.stdout=out
        print("\nfile %s written"  % args.file)
    
    sys.exit(0)

if __name__ == '__main__':
    """
        se questo script non viene importato, esegui la funzione main
    """
    main()
