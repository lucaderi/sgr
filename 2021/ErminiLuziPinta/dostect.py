import argparse
import os
import socket
import netifaces
from core.traffic import OfflineCatcher, LiveCatcher
from core.graph import Graph
import sys
import ipaddress
import signal
from core import utils
from datetime import datetime
import curses

# Check if the input file has a valid extension
def is_valid_capture(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        ext = os.path.splitext(arg)[-1].lower() # Get file extension

        if ext != ".pcap" and ext != ".pcapng": # Check supported extensions
             parser.error("The file %s is of an incorrect format" % arg)
        else:
            return arg  # Return an open file handle

# Check if the interface exists
def is_valid_interface(parser, arg):
    if arg in netifaces.interfaces():
        return arg
    else:
        parser.error("Interface %s not found" % arg)


def main():

    parser = argparse.ArgumentParser(description="DoSTect allow to detect SYN flooding attack with Parametric/Non Parametric CUSUM change point detection")
    
    # Create an exclusive group: in this group only one parameter can be used at time
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-i', '--interface', action='store', dest="interface",
                        help="Network interface from which to perform live capture",
                        metavar="INTERFACE",
                        type=lambda x: is_valid_interface(parser, x))

    source_group.add_argument('-f', '--file', action='store', dest="file",
                        help="Packet capture file", metavar="FILE .pcap/.pcapng",
                        type=lambda x: is_valid_capture(parser, x))

    parser.add_argument('-s', '--slice', dest='interval', action='store',default=5.0,
                        help="Specify duration of time interval observation in seconds (default: 5)")
   
    parser.add_argument("-p", "--parametric",  action='store', dest="param",type=bool, nargs='?',
                        const=True, default=False,
                        help="Flag to set CUSUM Parametric mode")

    parser.add_argument("-g", '--graph',  action='store', dest="graph",type=bool, nargs='?',
                        const=True, default=False,
                        help="Activate influxDB data sender: requires --interface")

    parser.add_argument('-t', '--threshold', action='store', dest="threshold",
                        help="Threshold detection value for CUSUM Parametric mode", type=float)
    
    parser.add_argument('-a', '--address', action='store', dest="address",
                        help=" IPv4 address of attacked machine for PCAP capture: requires --file", type=str)
    
    parser.add_argument("-v", "--verbose",  action='store', dest="verbose",type=bool, nargs='?',
                        const=True, default=False,
                        help="Flag to set verbose output mode")
    
    # Arguments parser
    args = parser.parse_args()

    #Check if can cast slice to int()
    try: 
        int(args.interval)
    except:
        parser.error("%s is not a valid integer time interval!" % str(args.interval))


    # Check if graph mode and file capture both selected
    if (args.graph and args.file is not None):
            parser.error("--graph unable to start with --file [FILE .pcap/.pcapng]")

    # Check file && localaddr dependency
    if (args.file and args.address is None) or (args.interface and args.address is not None):
        parser.error("--pcap requires --address [ADDRESS].")
    
    elif args.file is not None:
        # Check address format
        try: 
            ipaddress.IPv4Address(args.address)
        except:
            parser.error("%s is not an IPv4 address!" % str(args.address))

    # Initialize to default value if None
    if args.threshold is None:
        args.threshold = 5.0

    # Initialize to Graph module if -g mode
    plot = None
    if args.graph:
        try:
            plot = Graph(os.path.join(os.path.dirname(__file__), 'config/influxdb/config.ini'))
        except:
            utils.colors(7,0,"[Graph startup] - Error while connecting to influxdb instance: check your influxd service!", 12)
            sys.exit(1)

    # Set TERM for curses color support
    if os.getenv("TERM") is None:
        os.environ['TERM'] = "xterm-256color"

    # Start live capture if file is None (-i [INTERFACE] mode)
    if args.file is None:
        analyzer = LiveCatcher(
            source=str(args.interface),
            plot=plot,
            parametric=args.param,
            time_interval=int(args.interval),
            threshold=float(args.threshold),
            verbose=bool(args.verbose)
        )
    else:
        # Start analyzer from PCAP capture (-f [FILE] mode)
        analyzer = OfflineCatcher(
            source=str(args.file),
            ipv4_address=str(args.address),
            parametric=args.param,
            time_interval=int(args.interval),
            threshold=float(args.threshold),
            verbose=bool(args.verbose)
        )

    def sigint_handler(signum, frame):

        if args.graph:
            plot.stop_writing_thread()
        
        print_statistics()


        exit(0)

    def print_statistics():
        utils.colors(0,0,"                                                        ",5)
        utils.colors(0,0,"Status: monitoring ended",7)
        utils.colors(9,0,"Total intervals:           " + str(analyzer.get_total_intervals()),3)
        utils.colors(10,0,"Anomalous intervals count: " + str(analyzer.get_anomalous_intervals_count()),3)
        utils.colors(12,0,"Max volume reached:        " + str(analyzer.get_max_volume()),3)
        utils.colors(13,0,"Mean volume reached:       " + str(analyzer.get_mean_volume()),3)

        start_time = analyzer.get_time_start()
        end_time =  analyzer.get_time_end()

        if args.file is None and start_time != 0 and end_time != 0:
            utils.colors(14,0,"Attack start detected at:       " + str(datetime.fromtimestamp(start_time)),12)
            utils.colors(15,0,"End attack detected at:         " + str(datetime.fromtimestamp(end_time)),12)

    # Register handler for SIGINT
    signal.signal(signal.SIGINT, sigint_handler)
    
    try:
        # Start analyzer
        analyzer.start()
    except (KeyboardInterrupt, SystemExit):
        sys.exit()

    print_statistics()
   

if __name__ == "__main__":
    main()
