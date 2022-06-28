import argparse
import pandas as pd
import json
import numpy
import logging
import os
import matplotlib.pyplot as plt
import rrdtool
from datetime import datetime

# define possible RRA metrics
RRD_METRICS = ["AVERAGE", "MAX", "MIN", "LAST"]

def init_logger():
    """Init logger with error level"""

    # format the logging message
    # TIME - LOG LEVEL : message to print
    logging.basicConfig(format="%(asctime)s - %(levelname)s : %(message)s")

    # Creating logger object
    logger = logging.getLogger(__file__)

    # Setting the threshold of logger to INFO
    logger.setLevel(logging.INFO)

    return logger


def get_logger():
    """Returns a logger"""
    return logging.getLogger(__file__)


def get_parser() -> argparse.ArgumentParser:
    """Returns the program's argument parser"""

    def check_positive_integer(value):
        """Check if a value is positive"""
        int_value = int(value)
        if int_value <= 0:
            raise argparse.ArgumentTypeError("%s is not a positive value" % value)
        return int_value
    
    def check_greater_ten_integer(value):
        """Check if a value is greater than or equal to 10"""
        int_value = int(value)
        if int_value < 10:
            raise argparse.ArgumentTypeError("%s is not >= 10" % value)
        return int_value

    parser = argparse.ArgumentParser(description="Detect signal skewness")

    parser.add_argument(
        "-v",
        "--verbose",
        help="increase verbosity",
        action="store_true",
        dest="verbose",
    )

    parser.add_argument(
        "-p",
        "--print",
        help="print final graph",
        action="store_true",
        dest="print",
    )

    parser.add_argument(
        "-n",
        type=check_positive_integer,
        help="(positive) number of first elements to take in order to determine sample standard deviation",
        required=True,
        dest="sample_elements",
    )

    parser.add_argument(
        "-w",
        type=check_greater_ten_integer,
        help="number of elements inside the sliding window, must be greater than or equal to 10",
        required=True,
        dest="window_size",
    )

    parser.add_argument(
        "-s",
        type=check_positive_integer,
        help="time span (in seconds) (default is 8600 = 1 day)",
        default=86400,
        dest="time_span",
    )

    # JSON and rrd files are mutually exclusive
    action = parser.add_mutually_exclusive_group()

    action.add_argument(
        "--json",
        type=str,
        help="filename of a JSON time serie",
        dest="json_filename",
    )

    action.add_argument(
        "--rrd",
        type=str,
        help="filename of a RRD time serie",
        dest="rrd_filename",
    )

    # chosen metric
    parser.add_argument(
        "--rrd-metric",
        type=str,
        help="metric to take from a RRD time serie (default is AVERAGE)",
        choices=RRD_METRICS,
        default="AVERAGE",
        dest="rrd_metric",
    )

    parser.add_argument(
        "--rrd-ds-index",
        type=int,
        help="DS index of the RRD time serie (default is 0)",
        default=0,
        dest="rrd_ds_index",
    )

    return parser


def get_rrd_data(rrd_file, metric : str, time_span : int):
    """Get data from RRD database of the last day"""

    end_idx = int(rrdtool.last(rrd_file))
    start_idx = end_idx - time_span

    rrd_data = rrdtool.fetch(rrd_file, metric, "-e", str(end_idx), '-s', str(start_idx))

    start_time, end_time, step = rrd_data[0]
    ds = rrd_data[1]
    data = rrd_data[2]

    return start_time, end_time, step, ds, data


def detect_anomaly(data, sample_std_dev) -> bool:
    # get data standard deviation
    std_dev = float(numpy.std(data))

    return std_dev > (3 * sample_std_dev)


def skewness():
    """Find nervousness inside a time serie"""
    
    # init logger
    logger = init_logger()
    
    parser = get_parser()
    args = parser.parse_args()

    # if verbose mode is active show all logging messages
    if args.verbose:
        import logging

        logger.setLevel(logging.DEBUG)
        logger.info("Verbose mode is now active: show all messages")

    # returns if neither a json file nor an rrd file is provided
    if not args.json_filename and not args.rrd_filename:
        logger.error("Neither a json file nor an rrd file provided.")
        return
    
    dataframe = pd.DataFrame()
    
    # load json into pandas dataframe
    if args.json_filename:
        
        # print what file we're analyzing
        logger.info(f"Analyzing {args.json_filename}...")
        
        # check file existance
        if not os.path.exists(args.json_filename) or not os.path.isfile(args.json_filename):
            logger.error("JSON provided not exists or is not a file")
            return
        
        # load
        with open(args.json_filename, "r") as file:
            # get data from json
            data = json.loads(file.read())
            # insert data into dataframe
            dataframe = pd.read_json(data,typ='frame')
            #print(dataframe)
            #dataframe.plot()
            #plt.show()

    elif args.rrd_filename:

        # print what file we're analyzing
        logger.info(f"Analyzing {args.rrd_filename}...")

        # load rrd into pandas dataframe
        
        # check file existance
        if not os.path.exists(args.rrd_filename) or not os.path.isfile(args.rrd_filename):
            logger.error("RRD provided not exists or is not a file")
            return
        
        # get data
        start_time, end_time, step_size, ds, data = get_rrd_data(
            args.rrd_filename,
            args.rrd_metric,
            args.time_span
        )

        # get the selected RRA
        if len(ds) <= args.rrd_ds_index:
            logger.error(f"RRD ds index {args.rrd_ds_index} is out of range")
            exit()
        index = args.rrd_ds_index

        timestamp = start_time

        data_to_analyze = []

        for value in data:
            y = value[index]

            # don't write None elements
            data_to_analyze.append((datetime.fromtimestamp(timestamp), y))
            
            timestamp += step_size

        # pandas dataframe
        
        # get legend filename
        label = str(args.rrd_filename).split(".")[0]
        columns=['time', label]
        
        dataframe = pd.DataFrame(data_to_analyze, columns=columns)
        dataframe.set_index('time', drop=True, inplace=True)
        #print(dataframe)
    
    # get number of rows
    rows_count = len(dataframe.index)

    # check lenghts of sample elements and window size
    if args.sample_elements > rows_count:
        logger.error("Number of elements to calculate sample is greater than number of total rows")
        return

    if args.window_size > rows_count:
        logger.error("Window size is greater than number of total rows")
        return
    
    # get first SAMPLE_ELEMENTS data
    y_column = dataframe.columns[0]
    sample_data = dataframe.head(args.sample_elements)[y_column]

    # calculate standard deviation of these data
    sample_std_dev = numpy.std(sample_data)
    logger.debug(f"Sample std dev = {sample_std_dev}")

    # sliding window slides a tenth each time
    window_step = int(args.window_size / 10)
    logger.debug(f"Window step = {window_step}")

    # list of detected anomalies
    anomalies : list[tuple] = []

    for window_start in range(0, rows_count, window_step):
        # the window has at most WINDOW_SIZE elements
        window_end = window_start + args.window_size
        if window_end >= len(dataframe):
            window_end = len(dataframe) - 1
        
        if window_end == window_start:
            break

        # get data from dataframe
        batch_data = dataframe.iloc[window_start:window_end,]

        # margin x-values of the window
        index_start = dataframe.index[window_start]
        index_end = dataframe.index[window_end]
        
        # detect anomaly
        if detect_anomaly(batch_data, sample_std_dev):
            
            logger.info(f"Anomaly detected inside window between {index_start} and {index_end}")
            anomalies.append((index_start, index_end))
        else:

            logger.debug(f"No anomaly detected inside window between {index_start} and {index_end}")
    
    # plot only if requested
    if args.print:
        # retrieve axes
        ax = dataframe.plot(color='black', x_compat=True)
        
        # plot anomalies 
        for anomaly in anomalies:
            idx_start, idx_end = anomaly
            ax.axvspan(idx_start, idx_end, facecolor='red', alpha=0.10)
        
        plt.show()
    

if __name__ == '__main__':
    skewness()