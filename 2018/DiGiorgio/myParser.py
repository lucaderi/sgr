# encoding=utf8
# autore: Salvatore Costantino
# modificato da: Alessandro Di Giorgio
# mail: s.costantino5@studenti.unipi.it,
#       a.digiorgio1@studenti.unipi.it

import argparse

examples = """examples:
    ./eBPFlow.py                # trace all TCP connect()s, TCP accept()s, UDP send()s, UDP receive()s
    ./eBPFlow.py -p 181         # only trace PID 181
    ./eBPFlow.py -p 181,2342    # only trace PID 181 and 2342
    ./eBPFlow.py -P 80          # only trace port 80
    ./eBPFlow.py -P 80,81       # only trace port 80 and 81
    ./eBPFlow.py -R 80,100      # only trace ports in [80,100]
    ./eBPFlow.py -f <filepath>  # write output to file at <filepath>
    ./eBPFlow.py -d             # enable docker mode
"""

def parseArg():
    """
        parsatore argomenti linea di comando
    """
    parser = argparse.ArgumentParser(
        description="Trace TCP/UDP events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid",
        help="comma-separated list of PIDs to trace.")
    parser.add_argument("-R", "--rport",
        help="trace ports in a range (comma-separated extrema)")
    parser.add_argument("-P", "--port",
        help="comma-separated list of ports to trace.")
    parser.add_argument("-f","--file",
        help="write output to file")
    parser.add_argument("-d", action='store_true')
    args = parser.parse_args()
    return args
