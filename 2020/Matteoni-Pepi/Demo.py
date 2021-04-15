#!\bin\python3

import pyshark
import matplotlib.pyplot as plt
import matplotlib.dates as md
import json
import argparse
import sys
from datetime import datetime, timedelta, time
import APIForecast
import Utils

# Params
def parse_args():
    parser = argparse.ArgumentParser(description='Simple script that generates a plot based on an input dataset.json')
    data_parser = parser.add_mutually_exclusive_group(required=False)
    data_parser.add_argument('--dataset', type=str, required=False, default="NULL",
                             help='dataset from which the script reads the values')
    data_parser.add_argument('--pcap', type=str, required=False, default="NULL",
                             help='pcap from which the script reads the packets')
    parser.add_argument('--alpha', type=float, required=False, default=-1,
                        help='alpha parameter for forecasting')
    parser.add_argument('--beta', type=float, required=False, default=-1,
                        help='beta parameter for forecasting')
    parser.add_argument('--gamma', type=float, required=False, default=-1,
                        help='gamma parameter for forecasting')
    iter_parser = parser.add_mutually_exclusive_group(required=False)
    iter_parser.add_argument('--iterative', dest='iter', action='store_true',
                             help='iterates the fitting process 100 times and picks the best result (default)')
    iter_parser.add_argument('--no-iterative', dest='iter', action='store_false',
                             help='execs the fitting process just once')
    parser.set_defaults(iter=True)
    parser.add_argument('--season', type=int, required=False, default=-1,
                        help='points in a season for Holt-Winters forecasting')
    parser.add_argument('--rsi', type=int, required=False, default=12,
                        help='points for RSI calculation')
    parser.add_argument('--interval', type=int, required=False, default=30,
                        help='number of seconds for aggregation')
    return parser.parse_args()


def sse(values, predictions):
    val = 0
    for n, r in zip(values, predictions):
        val = val + ((n - r) ** 2)
    return val


Utils.printgreen("********************************************")
Utils.printgreen("************* DEMO     CAPTURE *************")
Utils.printgreen("********************************************")

# Arguments
args = parse_args()
dataset = args.dataset  # Dataset if present
pcap = args.pcap  # PCAP if present

start_time = datetime.now()
nums = []  # Data
dates = []  # Timestamps
count = 0  # Counting (output)
errors = 0  # Errors (output)
if dataset == "NULL" and pcap == "NULL":
    Utils.printyellow("\r\033[F\033[KPlease specify an input file")
    sys.exit(0)
else:
    if dataset != "NULL":
        Utils.printgreen("Loading dataset...\n")
        nums = json.load(open(dataset, "r"))
        n = 0
        now = datetime.combine(datetime.today(), time.min)
        for n in nums:
            count = count + 1
            dates.append(now)
            now = now + timedelta(minutes=5)
            Utils.printyellow("\r\033[F\033[KLoading\t" + "#" + str(count) + " " + str(n) + "B")

    elif pcap != "NULL":
        Utils.printgreen("Loading PCAP...\n")
        cap = pyshark.FileCapture(pcap)  # Reading from PCAP
        for pkt in cap:
            try:
                dates.append(float(pkt.frame_info.time_epoch))
                nums.append(int(pkt.length) / 1000)
                count += 1
                Utils.printyellow("\r\033[F\033[KLoading\t" + "#" + str(count) + " " + str(int(pkt.length)) + "B")
            except AttributeError:
                errors += 1
                continue

        # Aggregation
        interval = args.interval
        intervals = []
        series = []
        start = -1
        sum = 0
        j = 0
        for i in range(len(dates)):
            if start == -1:
                start = i
                sum += nums[i]
            else:
                elapsed = datetime.fromtimestamp(dates[i]) - datetime.fromtimestamp(dates[start])
                sum += nums[i]
                if elapsed.total_seconds() > interval:
                    j += 1
                    series.append(sum)
                    intervals.append(datetime.fromtimestamp(dates[i]))
                    lastdate = datetime.fromtimestamp(dates[i])
                    sum = 0
                    start = -1
        nums = series
        dates = intervals

elapsed = (datetime.now() - start_time)
print("\r\033[F\033[K", end="")
Utils.printyellow("Loaded\t" + str(count) + " data points in " + str(elapsed))  # Output
Utils.printyellow("\t" + str(errors) + " errors")
Utils.printyellow("\tFrom " + dates[0].strftime("%Y-%m-%d %H:%M") + " to " +
                  dates[len(dates) - 1].strftime("%Y-%m-%d %H:%M"))

# Parameters
alpha = args.alpha
beta = args.beta
gamma = args.gamma
lastdate = dates[len(dates) - 1]
count = len(nums)

if alpha != -1 and beta != -1 and gamma != -1:  # All parameters specified, Holt-Winters forecasting
    season = args.season
    if season == -1: season = len(nums) // 2  # TODO ugly
    res, dev, ubound, lbound = APIForecast.holt_winters(nums, season, alpha, beta, gamma, season)  # API
    RSI = APIForecast.rsi(nums, args.rsi)

    for f in res[len(nums):]:
        lastdate = lastdate + timedelta(minutes=5)
        dates.append(lastdate)

    SSE = sse(nums, res)
    MSE = SSE / count

    Utils.printgreen("\n\nHolt-Winters until " + dates[len(dates) - 1].strftime("%Y-%m-%d %H:%M:%S"))

    strSSE = "{:.5f}".format(SSE)
    strMSE = "{:.5f}".format(MSE)
    stralpha = "{:.5f}".format(alpha)
    strbeta = "{:.5f}".format(beta)
    strgamma = "{:.5f}".format(gamma)
    Utils.plot(nums, dates, res, ubound, lbound, RSI, "Holt-Winters forecasting (fitted alpha = " + stralpha +
               ", beta = " + strbeta + ", gamma = " + strgamma + ")\nSSE = " + strSSE + ", MSE = " + strMSE)
elif alpha != -1 and beta != -1:  # Only alpha and beta specified, Double Exponential forecasting
    res = APIForecast.double_exponential_smoothing(nums, alpha, beta)
    RSI = APIForecast.rsi(nums, args.rsi)

    for f in res[len(nums):]:
        lastdate = lastdate + timedelta(minutes=5)
        dates.append(lastdate)

    Utils.printgreen("\n\nDouble Exponential until " + dates[len(dates) - 1].strftime("%Y-%m-%d %H:%M:%S"))

    Utils.plot(nums, dates, res, None, None, RSI, "Double Exponential forecasting (alpha = " +
               str(alpha) + ", beta = " + str(beta) + ")")
elif alpha != -1:  # Only alpha specified, Single Exponential forecasting
    res = APIForecast.exponential_smoothing(nums, alpha)
    RSI = APIForecast.rsi(nums, args.rsi)

    dates.append(lastdate + timedelta(seconds=5))

    Utils.printgreen("\n\nSingle Exponential until " + dates[len(dates) - 1].strftime("%Y-%m-%d %H:%M:%S"))

    Utils.plot(nums, dates, res, None, None, RSI, "Single Exponential forecasting (alpha = " + str(alpha) + ")")
else:  # No parameters specified, exiting
    Utils.printgreen("\nNo parameters specified")
