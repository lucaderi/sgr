import argparse
import json
from random import *


def parse_args():
    parser = argparse.ArgumentParser(description="Create a dataset or an anomalous dataset for testing")
    data_parser = parser.add_mutually_exclusive_group(required=False)
    data_parser.add_argument("--type", type=str, required=False, default="NULL",
                            help="<normal> for a normal dataset or <anomalous> whit a anomalous day")
    data_parser.add_argument("--days", type=int, required=False, default=5,
                            help = "number of days")
    data_parser.add_argument("--pcap", type=str, required=False, default="NULL",
                            help = "condenses the input pcap into a dataset with 5m intervals")
    return parser.parse_args()


# Create a dataset for a day
def createDataset():
    dataset = []
    for i in range(108): # 00 to 09
        dataset.append(randint(0,10))
    for i in range(48): # 09 to 13 (Work)
        elem = randint(80,90)
        dataset.append(elem)
    for i in range(12): # 13 to 14
        elem = randint(0,10)
        dataset.append(elem)
    for i in range(48): # 14 to 18 (Work)
        elem = randint(70,80)
        dataset.append(elem)
    for i in range(36): # 18 to 21
        elem = randint(0,10)
        dataset.append(elem)
    for i in range(24): # 21 to 23 (It's time for Netflix)
        elem = randint(340,350)
        dataset.append(elem)
    for i in range(12): # 23 to 24
        dataset.append(randint(0,10))
    return dataset


# Create a anomalous dataser for a day
def createAnomalousDataset():
    dataset = []
    for i in range(108): # 00 to 09
        dataset.append(randint(0,10))
    for i in range(48): # 09 to 13 (Work)
        elem = randint(340,350)
        dataset.append(elem)
    for i in range(12): # 13 to 14
        elem = randint(0,10)
        dataset.append(elem)
    for i in range(48): # 14 to 18 (Work)
        elem = randint(70,80)
        dataset.append(elem)
    for i in range(36): # 18 to 21
        elem = randint(0,10)
        dataset.append(elem)
    for i in range(24): # 21 to 23 (It's time for Netflix)
        elem = randint(340,350)
        dataset.append(elem)
    for i in range(12): # 23 to 24
        dataset.append(randint(0,10))
    return dataset


def dataToJson(dataset, filename):
    outfile = open(filename, "w")
    json.dump(dataset, outfile, indent=4)
    outfile.close()


def dataFromJson(filename):
    infile = open(filename, "r")
    dataset = json.load(infile)
    return dataset


args = parse_args()
datasetType = args.type
pcap = args.pcap
numdays = args.days
dataset = []
if (datasetType == "series"):
    for i in range(numdays):
        dataset += createDataset()
    print("Dataset created")
    dataToJson(dataset, "dataset.json")
elif(datasetType == "anomalous"):
    dataset = createAnomalousDataset()
    print("Anomalous day Dataset created")
    dataToJson(dataset, "anomalousDay.json")
elif(datasetType == "normal"):
    dataset = createDataset()
    print("Normal day Dataset created")
    dataToJson(dataset, "normalDay.json")
elif(pcap != "NULL"):
    import pyshark
    from datetime import datetime
    dates, series, interval = [], [], 300
    cap = pyshark.FileCapture(pcap)
    for pkt in cap:
        try:
            dates.append(float(pkt.frame_info.time_epoch))
            series.append(int(pkt.length) / 1000)
            print("\r\033[F\033[KReading " + str(series[-1]) + " " + datetime.fromtimestamp(dates[-1]).strftime("%Y-%m-%d %H:%M"))
        except AttributeError:
            continue
    print("\n\tFrom " + datetime.fromtimestamp(dates[0]).strftime("%Y-%m-%d %H:%M") + " to " + datetime.fromtimestamp(dates[-1]).strftime("%Y-%m-%d %H:%M")+"\n\n")
    intervals = []
    newseries = []
    start = -1
    sum = 0
    for i in range(len(dates)):
        if start == -1:
            start = i
            sum += series[i]
        else:
            elapsed = datetime.fromtimestamp(dates[i]) - datetime.fromtimestamp(dates[start])
            sum += series[i]
            if elapsed.total_seconds() > 300:
                newseries.append(sum)
                intervals.append(datetime.fromtimestamp(dates[i]))
                lastdate = datetime.fromtimestamp(dates[i])
                sum = 0
                start = -1
                print("\r\033[F\033[KCondensating " + str(i - start) + " points: " + str(newseries[-1]) + "\n")
    series = newseries
    dates = intervals
    dataToJson(series, pcap + ".json")
else:
    print("Dataset not created")
