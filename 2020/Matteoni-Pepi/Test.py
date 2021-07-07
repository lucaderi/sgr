import json
import APIForecast as api
import Utils as u
import CreateDatasets
from datetime import datetime, time, timedelta
from random import *

# Custom print and input
def inputYellow(str):
    CEND = '\33[0m'
    CYELLOW = '\33[33m'
    r = input(CYELLOW + str + CEND)
    return r

def printYellow(str):
    CEND = '\33[0m'
    CYELLOW = '\33[33m'
    print(CYELLOW + str + CEND)

def printGreen(str):
    CEND = '\33[0m'
    CGREEN  = '\33[32m'
    print(CGREEN + str + CEND)

# MAIN
print("")
printGreen("********************************************")
printGreen("******************* TEST *******************")
printGreen("********************************************")

# Creazione Dataset
printYellow("Generazione del dataset")
dataset = "dataset.json"
series = json.load(open(dataset, "r"))
intervals = []
interval = 300 # 5 minuti
now = datetime.combine(datetime.today(), time.min)
for i in series:
    intervals.append(now)
    now = now + timedelta(0, interval)
lastdate = now

# Test Holt-Winters
printYellow("\nHolt-Winters")
n_preds = 288
slen = 288

alpha = 0.7
beta = 0.0000000000000000000000000000000000001
gamma = 0.8

printYellow("\talpha =\t" + str(alpha) + "\n\tbeta = \t" + str(beta) + "\n\tgamma =\t" + str(gamma))

for i in range (n_preds):
    lastdate = lastdate + timedelta(0, interval)
    intervals.append(lastdate)
res, dev, ubound, lbound = api.holt_winters(series, slen, alpha, beta, gamma, n_preds)

#Experimental
printYellow("\nForecasting su nuovo dataset generato")
anomalousDay = CreateDatasets.createAnomalousDataset()
forecastDeviation = []
forecastubound, forecastlbound = api.forecast_bounds(res, anomalousDay, dev, len(series), gamma)

series += anomalousDay
ubound += forecastubound
lbound += forecastlbound

u.plot(series, intervals, res, ubound, lbound, None, f"alpha ={alpha}, beta = {beta}, gamma = {gamma}")

