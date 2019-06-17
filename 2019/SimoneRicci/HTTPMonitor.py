import optparse
import sys
import threading
from time import sleep
from HTTPStats import *
import socket
import traceback

import scapy.all as sc
import scapy_http.http
from scapy.sendrecv import sniff
from scapy.config import conf
from scapy.data import ETH_P_ALL


def parse_argv():
    parser = optparse.OptionParser(description='HTTP traffic analyzer')
    parser.add_option('-t', '--time', help='Time to sniff (in seconds)')
    parser.add_option('-M', '--minutes', help='Time expressed in minutes', default=False, action='store_true', dest='minutes')
    parser.add_option('-H', '--hour', help='Time expressed in minutes', default=False, action='store_true', dest='hours')
    parser.add_option('-f', '--file', help='File pcap (Use only once between -f and -t')
    parser.add_option('-m', '--host', help='Target host. (Use only with -f option)', default=None)
    parser.add_option('-i', '--interface', help='Interface of capture', default='eth0')
    parser.add_option('-r', '--resolve', help='Resolve IP addresses', default=False, action='store_true', dest='resolve')
    parser.add_option('-v', '--verbose', help='Ability verbose mode', default=False, action='store_true', dest='verbose')

    options, args = parser.parse_args()

    options.ipv4 = True

    if options.time != None and options.file != None:
        print('Use only one of -f and -t', file=sys.stderr)
        sys.exit(1)

    if not options.time != None and not options.file != None:
        print('Use at least one of -f and -t', file=sys.stderr)
        sys.exit(1)

    return options


def offline_analisys(file, buffer, target_ip, verbose=False):
    if verbose:
        print('Reading pcap file...')
    packets = sniff(offline=file)
    for p in packets:
        ip = p.getlayer('IP')
        tcp = p.getlayer('TCP')
        if ip != None and tcp != None:
            if (ip.src == target_ip or ip.dst == target_ip) and \
                    (tcp.sport in (80, 443) or tcp.dport in (80, 443)):
                buffer.add_packet(p)

def online_analisys(buffer, stopper, interface, target_ip, verbose=False):
    filter = '(tcp port 80 or tcp port 443) and host {}'.format(target_ip)
    socket = conf.L2listen(
        type=ETH_P_ALL,
        iface=interface,
        filter=filter
    )
    if verbose:
        print('Sniffing packets...')
    cb = lambda pkt: buffer.add_packet(pkt, verbose)
    while not stopper.isSet():
        sniff(opened_socket=socket,
              prn=cb,
              timeout=1, store=1)


def main():
    args = parse_argv()
    target_ip4 = args.host if args.host != None and args.file != None else socket.gethostbyname(socket.gethostname())
    buff = ClientStats([target_ip4])
    if args.file != None:
        offline_analisys(args.file, buff, str(target_ip4), args.verbose)
    else:
        STOP = threading.Event()
        # converto il tempo in secondi
        if args.hours:
            molt = 3600
        elif args.minutes:
            molt = 60
        else:
            molt = 1
        sniff_secs = int(args.time) * molt

        # avvio il thread sniffer
        sniffer = threading.Thread(target=online_analisys,
                                   args=(buff, STOP, args.interface, str(target_ip4), args.verbose))
        sniffer.start()

        # attendo che trascorra il tempo desiderato
        if sniffer.is_alive():
            sleep(int(sniff_secs))
        STOP.set()
        sniffer.join()
    if args.verbose:
        print('\n\n' + '-' * 15 + ' STATS ' + '-' * 15 + '\n')
    buff.print(args.resolve)


if __name__ == '__main__':
    main()
