#!/usr/bin/python
# encoding=utf8
# autore: Salvatore Costantino, Alessandro Di Giorgio
# mail: s.costantino5@studenti.unipi,
#       a.digiorgio1@studenti.unipi.it
# fonti
    # https://github.com/iovisor/bcc/blob/master/tools/tcpaccept.py
    # https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py
    # https://github.com/22RC/eBPF-TcpLatency-NetPagefault/blob/master/NetPagefault/source_UDPtracer.c

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
from functools import partial
import UDP_BPFCode
import DockerManager

# event data
TASK_COMM_LEN = 16      # linux/sched.h

#struttura per conservare dati che arrivano dal kernel(IPv4)
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("uid", ct.c_ulonglong),
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
        ("uid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("port", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

TABLE_DIM=43 #dimensione tabella hash

#tabella hash flussi TCP connect() / UDP send()
outTable=SimpleFlowTable(TABLE_DIM)

#tabella hash dei flussi TCP accept() / UDP receive()
inTable=SimpleFlowTable(TABLE_DIM)


def print_out_event(ip_v, table, proto4, cpu, data, size):
    if (ip_v != 4 and ip_v != 6): return
    try:
        event = ct.cast(data,
                ct.POINTER(Data_ipv4 if ip_v == 4 else Data_ipv6)).contents
        table.insert(event.pid, event.uid, event.task.decode(), event.ip,
            inet_ntop(AF_INET if ip_v == 4 else AF_INET6,
                      pack("I", event.saddr) if ip_v == 4 else event.saddr),
            inet_ntop(AF_INET if ip_v == 4 else AF_INET6,
                      pack("I", event.daddr) if ip_v == 4 else event.daddr),
            proto4,
            event.port)
    except (UnicodeDecodeError,ValueError,error,TypeError,er):
        return

def print_in_event(ip_v, table, proto4, cpu, data, size):
    if (ip_v != 4 and ip_v != 6): return
    try:
        event = ct.cast(data,
                ct.POINTER(Data_ipv4 if ip_v == 4 else Data_ipv6)).contents
        table.insert(event.pid, event.uid, event.task.decode(),event.ip,
            inet_ntop(AF_INET if ip_v == 4 else AF_INET6,
                      pack("I", event.daddr) if ip_v == 4 else event.daddr),
            inet_ntop(AF_INET if ip_v == 4 else AF_INET6,
                      pack("I", event.saddr) if ip_v == 4 else event.saddr),
            proto4,
            event.port)
    except (UnicodeDecodeError,ValueError,error,TypeError,er):
        return

# TCP (connect/accept)

print_ipv4_c_event = partial(print_out_event, 4, outTable, 0)
print_ipv6_c_event = partial(print_out_event, 6, outTable, 0)
print_ipv4_a_event = partial(print_in_event, 4, inTable, 0)
print_ipv6_a_event = partial(print_in_event, 6, inTable, 0)

# UDP (send/receive)

print_ipv4_s_event = partial(print_out_event, 4, outTable, 1)
print_ipv6_s_event = partial(print_out_event, 6, outTable, 1)
print_ipv4_r_event = partial(print_in_event, 4, inTable, 1)
print_ipv6_r_event = partial(print_in_event, 6, inTable, 1)

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

    if args.d:
        DockerManager.enabled = True

    bpf_text = BPFCode.text  #definizione codice BPF

    bpf_text=filter(args,bpf_text) #filtraggio in codice BPF

    print("compiling...")

    # initialize BPF
    tcp_b = BPF(text=bpf_text)
    udp_b = BPF(text=filter(args,UDP_BPFCode.text))

    #associo funzione <fn_name> a chiamata del kernel <event> (in modo che <fn_name> venga chiamata quando occore <event>)
    tcp_b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    tcp_b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    tcp_b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

    # apertura buffer circolare per comunicazioni kernel->user-space (per i vari "eventi" da monitorare)
    # ed associazione callback
    tcp_b["ipv4_connect_events"].open_perf_buffer(print_ipv4_c_event)
    tcp_b["ipv6_connect_events"].open_perf_buffer(print_ipv6_c_event)
    tcp_b["ipv4_accept_events"].open_perf_buffer(print_ipv4_a_event)
    tcp_b["ipv6_accept_events"].open_perf_buffer(print_ipv6_a_event)


    udp_b.attach_kprobe(event="udp_sendmsg", fn_name="trace_send_entry")
    udp_b.attach_kretprobe(event="udp_sendmsg", fn_name="trace_send_v4_return")
    udp_b.attach_kretprobe(event="udpv6_sendmsg", fn_name="trace_send_v6_return")

    udp_b.attach_kretprobe(event="udp_recvmsg",fn_name="trace_receive_v4")
    udp_b.attach_kretprobe(event="udpv6_recvmsg",fn_name="trace_receive_v6")

    # callback udp
    udp_b["ipv4_send_events"].open_perf_buffer(print_ipv4_s_event)
    udp_b["ipv6_send_events"].open_perf_buffer(print_ipv6_s_event)
    udp_b["ipv4_receive_events"].open_perf_buffer(print_ipv4_r_event)
    udp_b["ipv6_receive_events"].open_perf_buffer(print_ipv4_r_event)

    signal.signal(signal.SIGINT, signal_handler) #installo signal handler

    print("working... Press CTRL-C to print results")
    while flag==True: #fin tanto che non ricevo SIGINT
        tcp_b.kprobe_poll() # polls from all open perf ring buffers
        udp_b.kprobe_poll()

    f=None
    if args.file: # se scrittura su file
        try:
            f=open(args.file,'w')

            # lavoro sui descrittori
            out=sys.stdout
            sys.stdout=f
        except IOError:
            print("\nimpossibile scrivere il file specificato: %s" % args.file)

    print("\nOutbound flows (TCP connect, UDP send)\n"
          "%-6s %-26.26s %-10.10s %-2s %-5s %-30s %-30s %-6s %-5s %s" %
          ("PID","COMM", "USER", "IP", "PROTO", "SADDR", "DADDR", "RPORT", "COUNT", "MTBS(s)"))
    outTable.readTable()

    print("\nInbound flows (TCP accept, UDP receive)\n"
          "%-6s %-26.26s %-10.10s %-2s %-5s %-30s %-30s %-6s %-5s %s" %
          ("PID","COMM", "USER", "IP", "PROTO", "SADDR", "DADDR", "LPORT", "COUNT", "MTBS(s)"))
    inTable.readTable()

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
