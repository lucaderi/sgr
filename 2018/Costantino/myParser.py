# encoding=utf8
# autore: Salvatore Costantino
# mail: s.costantino5@studenti.unipi.it

import argparse

examples = """examples:
    ./eBPF_TCPFlow.py                # trace all TCP connect()s and TCP accept()s
    ./eBPF_TCPFlow.py -p 181         # only trace PID 181
    ./eBPF_TCPFlow.py -P 80          # only trace port 80
    ./eBPF_TCPFlow.py -P 80,81       # only trace port 80 and 81
    ./eBPF_TCPFlow.py -R 80,100      # only trace ports in [80,100]
    ./eBPF_TCPFlow.py -f <filepath>  # write output to file at <filepath>   
"""

def parseArg():
    """
        parsatore argomenti linea di comando
    """
    parser = argparse.ArgumentParser(
        description="Trace TCP connects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid",
        help="trace this PID only")
    parser.add_argument("-R", "--rport",
        help="trace ports in a range (comma-separated extrema)")
    parser.add_argument("-P", "--port",
        help="comma-separated list of ports to trace.")
    parser.add_argument("-f","--file",
        help="write output to file")
    args = parser.parse_args()
    return args