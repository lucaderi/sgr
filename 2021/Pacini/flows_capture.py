import nfstream
import sys, getopt
import json

with open('config.json', 'r') as fd:
    j = json.load(fd)
    OUT_FILENAME = j['out_file']

# Export the received flows in the ".csv" format
def print_pandas_flows(my_streamer):
    df = my_streamer.to_pandas()
    df.to_csv(OUT_FILENAME)

# Parse command-line arguments
def parse_cmdline_args(argv):
    interface = "null"
    usage = "Usage: flows_capture.py -i <capture_interface>"

    # No arguments/flag in input
    if len(argv) == 0:
        print(usage)
        sys.exit()

    try:
        opts, args = getopt.getopt(argv, "hi:", ["help=", "interface="])
    except getopt.GetoptError:
        print("Error")
        sys.exit(2)
    
    # Parsing arguments
    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(usage)
            sys.exit()
        elif opt in ['-i', '--interface']:
            interface = arg

    if interface == "null":
        print(usage)
        sys.exit()

    return interface

if __name__ == "__main__":
    # Get command-line arguments
    interface = parse_cmdline_args(sys.argv[1:])

    # Activate metering processes
    my_streamer = nfstream.NFStreamer(source=interface,
            bpf_filter=None,
            snapshot_length=1600,
            idle_timeout=120,
            active_timeout=1800,
            udps=None,
            statistical_analysis=False)

    # Export the flows using pandas in a .csv format
    print_pandas_flows(my_streamer)


