import json
import pyshark
import Utils
import APIForecast
from datetime import datetime, timedelta, time

Utils.printgreen("********************************************")
Utils.printgreen("************* DEMO INTERACTIVE *************")
Utils.printgreen("********************************************")

start_time = datetime.now()
series = []  # Data
dates = []  # Timestamps
interval = 300  # 5 minutes

Utils.printyellow("Do you want to read a pcap or json file?")
Utils.printyellow(" 1 -- pcap")
Utils.printyellow(" 2 -- json")
choice = int(input())
if (choice == 1):
    Utils.printyellow("Path:")
    path = input()
    cap = pyshark.FileCapture(path)
    for pkt in cap:
        dates.append(float(pkt.frame_info.time_epoch))
        series.append(int(pkt.length) / 1000)
    intervals = []
    newseries = []
    start = -1
    sum, j = 0, 0
    for i in range(len(dates)):
        if start == -1:
            start = i
            sum += series[i]
        else:
            elapsed = datetime.fromtimestamp(dates[i]) - datetime.fromtimestamp(dates[start])
            sum += series[i]
            if elapsed.total_seconds() > interval:
                j += 1
                newseries.append(sum)
                intervals.append(datetime.fromtimestamp(dates[i]))
                lastdate = datetime.fromtimestamp(dates[i])
                sum = 0
                start = -1
    series = newseries
    dates = intervals

elif(choice == 2):
    Utils.printyellow("Path:")
    path = input()
    series = json.load(open(path, "r"))
    now = datetime.combine(datetime.today(), time.min)
    for i in series:
        dates.append(now)
        now = now + timedelta(0, interval)

    lastdate = dates[-1]

stop = False
while(stop == False):
    command = Utils.inputyellow("[plotSE, plotDE, plotHW, plotHW+, plotRSI, plotRSI-, exit]\nCommand: ")
    if(command == "plotSE"):
        alpha = float(Utils.inputyellow("Input alpha: "))
        res = APIForecast.exponential_smoothing(series, alpha)
        datesSE = []
        datesSE += dates
        datesSE.append(lastdate + timedelta(minutes=5))
        Utils.plotSDE(values=series, dates=datesSE, predictions=res, title=f"Exponential Smoothing, alpha={alpha}")
    elif(command == "plotDE"):
        alpha = float(Utils.inputyellow("Input alpha: "))
        beta = float(Utils.inputyellow("Input beta: "))
        res = APIForecast.double_exponential_smoothing(series, alpha, beta)
        datesDE = []
        datesDE += dates
        for i in res[len(series):]:
            lastdate = lastdate + timedelta(minutes=5)
            datesDE.append(lastdate)
        Utils.plotSDE(series, datesDE, res, f" Double Exponential Smoothing, alpha={alpha}, beta={beta}")
    elif(command == "plotHW"):
        alpha = float(Utils.inputyellow("Input alpha: "))
        beta = float(Utils.inputyellow("Input beta: "))
        gamma = float(Utils.inputyellow("Input gamma: "))
        slen = int(Utils.inputyellow("Input slen: "))
        n_preds = int(Utils.inputyellow("Input n_preds: "))
        datesHW = dates
        #TODO clear lastdate
        for i in range (n_preds):
            lastdate = lastdate + timedelta(minutes=5)
            datesHW.append(lastdate)
        res, dev, ubound, lbound = APIForecast.holt_winters(series, slen, alpha, beta, gamma, n_preds)
        Utils.plot(series, datesHW, res, ubound, lbound, None, f"alpha ={alpha}, beta = {beta}, gamma = {gamma}")
    elif(command == "plotHW+"):
        path = Utils.inputyellow("Input path: ")
        realSeries = json.load(open(path, "r"))
        alpha = float(Utils.inputyellow("Input alpha: "))
        beta = float(Utils.inputyellow("Input beta: "))
        gamma = float(Utils.inputyellow("Input gamma: "))
        slen = int(Utils.inputyellow("Input slen: "))
        n_preds = int(Utils.inputyellow("Input n_preds: "))
        datesHW = dates
        #TODO clear lastdate
        for i in range (n_preds):
            lastdate = lastdate + timedelta(minutes=5)
            datesHW.append(lastdate)
        res, dev, ubound, lbound = APIForecast.holt_winters(series, slen, alpha, beta, gamma, n_preds)
        forecastubound, forecastlbound = APIForecast.forecast_bounds(res, realSeries, dev, len(series), gamma)
        series += realSeries
        ubound += forecastubound
        lbound += forecastlbound
        Utils.plot(series, datesHW, res, ubound, lbound, None, f"alpha ={alpha}, beta = {beta}, gamma = {gamma}")
    elif(command == "plotRSI"):
        N = int(Utils.inputyellow("Input N: "))
        rsi = APIForecast.rsi(series, N)
        Utils.plot(series, dates, None, None, None, rsi, None)
    elif(command == "plotRSI-"):
        N = int(Utils.inputyellow("Input N: "))
        rsi = APIForecast.rsi(series, N)
        Utils.plotRSI(rsi, dates, None)
    elif(command == "exit"):
        stop = True
    else:
        Utils.printyellow("Command not recognized. Try again!")
