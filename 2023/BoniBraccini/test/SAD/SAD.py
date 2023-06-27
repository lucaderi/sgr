import pandas as pd
from prophet import Prophet
import json
import requests
import schedule
import scipy.stats as stats
import time
import re
import math
import datetime
from datetime import datetime, timedelta
from collections import deque
from prometheus_client import start_http_server, Gauge

import pickle

MAX_INTEVALS = 20160  # will overwrite delta values older than 7 days
DELTA_DB = deque(maxlen=MAX_INTEVALS)


COLLECTOR_ADDRESS = "demo" #insert your address or leave "demo" to use demo server
PROMETHEUS_ADRESS = "demo" #insert your address or leave "demo" to use demo server

demo_domain1 = ['https://prometheus', '.edipen.','it']
demo_domain2 = ['https://honeytest', '.edipen.','it']

if PROMETHEUS_ADRESS == "demo":
   PROMETHEUS_ADRESS = ''.join(demo_domain1)

if COLLECTOR_ADDRESS == "demo":
   COLLECTOR_ADDRESS = ''.join(demo_domain2)

def trainProphetModel(days):
    print("Training Prophet model...")
    print ("Collecting data from Prometheus DB")
    url = PROMETHEUS_ADRESS + "/api/v1/query_range"
    todayDate = datetime.utcnow().replace(hour=23, minute=59, second=0, microsecond=0)
    end_date = todayDate - timedelta(days=1) #yesterday at 23.59 is the last training data usable
    start_date = end_date - timedelta(days=days)
    
    params = {
        "query": 'Cowrie_SSH_connections{instance="100.101.217.66:8001"}',
        "start": start_date.isoformat() + "Z",
        "end": end_date.isoformat() + "Z",
        "step": "2m"
    }

    headers = {
        "Accept": "application/json"
    }

    response = requests.get(url, params=params, headers=headers)
    jsonData = response.json()
    #extract the data values (timeseries data)
    dataValues = jsonData['data']['result'][0]['values'] 
    #import dataValues to pansas
    importedData = pd.DataFrame(dataValues, columns=['ds', 'y'])
    #set dateStamp to pandas date unit
    importedData['ds'] = pd.to_datetime(importedData['ds'], unit='s')
    #Forecasting -- Prophet
    # Create a Prophet model and fit the data
    model = Prophet()
    model.fit(importedData)
    return model
  
def trainHoltWilterModel(days):
    url = PROMETHEUS_ADRESS + "/api/v1/query_range"
    todayDate = datetime.utcnow()
    end_date = todayDate #- timedelta(seconds=10) #30 seconds ago data 
    start_date = end_date - timedelta(days=days)# gather 4 days data 

    params = {
        "query": 'Cowrie_SSH_connections{instance="100.101.217.66:8001"}',
        "start": start_date.isoformat() + "Z",
        "end": end_date.isoformat() + "Z",
        "step": "30s"
    }

    headers = {
        "Accept": "application/json"
    }

    response = requests.get(url, params=params, headers=headers)
    jsonData = response.json()
    #extract the data values (timeseries data)
    dataValues = jsonData['data']['result'][0]['values'] 
    #import dataValues to pansas
    data = pd.DataFrame(dataValues, columns=['ds', 'y'])
    #set dateStamp to pandas date unit
    data['ds'] = pd.to_datetime(data['ds'], unit='s')
    #Forecasting -- Prophet
    # Create a Prophet model and fit the data
    return data

def forecastHoltWinter(data, PREDICTION_TIME):
    alpha = 0.18  # Smoothing factor for level
    beta = 0.14  # Smoothing factor for trend
    gamma = 0.17  # Smoothing factor for seasonality
    level = []
    trend = []
    seasonality = []
    # initialize the Level, Trend, and Seasonality for the 1st iteration (without trend factors)
    init_level = int(data.iloc[0]['y'])
    init_trend = (int(data.iloc[1]['y']) - int(data.iloc[0]['y'])) / 2
    level.append(init_level)
    trend.append(init_trend)
    seasonality.append(int(data.iloc[0]['y']) - init_level)

    # compute Triple Smoothing for the database
    obs_number = len(data)
    for obs in range(1, obs_number):
        yx = int(data.iloc[obs]['y'])  # x-th observation
        # Compute i-th level
        lx = alpha * yx + (1 - alpha) * (level[obs - 1] + trend[obs - 1])
        # Compute Trend
        bx = beta * (lx - level[obs - 1]) + (1 - beta) * trend[obs - 1]
        # Compute Seasonality
        sx = gamma * (yx - lx) + (1 - gamma) * seasonality[obs - 1]
        # Store the computed data
        level.append(lx)
        trend.append(bx)
        seasonality.append(sx)

    # compute the forecast using the last level, trend, and seasonality
    actual_level = level[-1]
    actual_trend = trend[-1]
    actual_seasonality_index = len(seasonality)-1
    # compute the forecasted value using the provided formula
    predicted_forecast = 0
    predicted_forecast = actual_level + PREDICTION_TIME * actual_trend + seasonality[( actual_seasonality_index - len(level) + 1 + ((PREDICTION_TIME-1) % len(level)))]
    if predicted_forecast < 0 :
      predicted_forecast = 0
    return predicted_forecast

def forecast(PREDICTION_TIME,model) :
    # Generate future dates with 1-hour intervals for Intrerval sec from now
    now = datetime.utcnow()
    future_time = now + timedelta(seconds=PREDICTION_TIME)
    future = pd.DataFrame({'ds': [future_time]})
    forecast = model.predict(future)
    predicted_forecast = forecast['yhat'].values[0]
    #print("New predcited value: " +  str(round(predicted_forecast)))
    #print("Waiting for actual value")
    return  round(predicted_forecast)

def update_threshold(STD_DEV_TIMES):
    global threshold
    total = 0
    for value in DELTA_DB:
        total += value
    mean = float(total) / len(DELTA_DB)
    variance = float(sum((x - mean) ** 2 for x in DELTA_DB) / len(DELTA_DB))
    std_dev =  float(variance ** 0.5)
    threshold = mean + (STD_DEV_TIMES * std_dev)
def get_z_value(confidence_level):
    confidence = confidence_level / 100
    alpha = 1 - confidence
    z_value = stats.norm.ppf(1 - alpha/2)
    return z_value

def get_required_delta_n(z_value):
    total = sum(DELTA_DB)
    mean = total / len(DELTA_DB)
    if mean == 0:
        return 0
    variance = sum((x - mean) ** 2 for x in DELTA_DB) / len(DELTA_DB)
    std_dev = math.sqrt(variance)
    confidence_width = 2 * std_dev / math.sqrt(len(DELTA_DB))
    delta_n = (z_value * std_dev / confidence_width) ** 2
    return delta_n

def getLastData():
  #downloading collector last data value
  try:
    collectorIP=COLLECTOR_ADDRESS
    response = requests.get(collectorIP)
    content = response.text
    #extract metric
    target_metric = 'Cowrie_SSH_connections'
    pattern = rf"{target_metric}\s+(\d+\.\d+)"
    match = re.search(pattern, content)
    
    if match:
        instant_value = float(match.group(1))
    return instant_value
  except Exception as e:
    print(e)
    print("Error collecting metrics from pormethues")
    return 0


def load_delta_db():
   global DELTA_DB
   try:
     with open("delta_values_DB.pkl", "rb") as file:
      DELTA_DB = pickle.load(file)
      print(str(len(DELTA_DB)) + " delta values loaded from backup")
      return DELTA_DB
   except :
    print("No existing backup found")

def load_config():
    try:
        with open("SAD.conf", "r") as file:
            config = []
            for line in file:
                line = line.strip()
                parts = line.split(":")
                value = parts[0].strip()
                config.append(value)
            algo =  int(config[0])
            days = config[1]
            t_time = config[2]
            train = config[3]
            acc = config[4] 
            if algo in [1, 2] and days.isdigit() and t_time.isdigit() and int(t_time) >= 0 :
             if (algo == 1 and 1 <= int(days) <= 7) or (algo == 2 and 1 <= int(days) <= 3):
                if train == 'N':
                    return config
                elif train == 'Y' and acc.isdigit() and 1 <= int(acc) <= 99:
                    return config
             else: 
                print("Invalid config values")
                return None
            else:
                print("Config contains syntax errors")
                return None
    except:
        print("No config file found, falling back to user input")
        return None
        


def save_data():
    with open("delta_values_DB.pkl", "wb") as file:
        pickle.dump(DELTA_DB, file)
        print("Saving delta values...")   

delta_gauge = Gauge("Cowrire_Prophet_connections_Delta","Delta value ")
threshold_gauge = Gauge("Cowrire_Prophet_connections_Threshold","Delta value Threshold")
anomaly_gauge = Gauge("Cowrire_Prophet_connections_Anomaly","Anomaly detected")
threshold_gauge.set(float('nan'))

TIME_DELTA = 30
STD_DEV_TIMES = 3 # How many standards deviations to add to the mean to calculate threshold, 3 is default( Three sigma rule default)
days = userChoice = threshold = confidence_level= 0
PRED_ALG = t_time = -1
prophet = None

loaded_config = load_config()
if loaded_config:
    PRED_ALG = int(loaded_config[0])
    days = int(loaded_config[1])
    t_time = int(loaded_config[2])
    userChoice = loaded_config[3]
    if userChoice == "Y":
       confidence_level = int(loaded_config[4])
    print("Config loaded successfully")

while PRED_ALG != 1 and PRED_ALG != 2:
 PRED_ALG = int(input("Choose prediction algorithm: \n 1) Prophet\n 2) Holt-Winters \n"))
while days == 0 or not isinstance(days, int) or (days > 7 and PRED_ALG == 1 ) or (days > 3 and PRED_ALG == 2):
   try: 
    if PRED_ALG == 1:
     days = int(input("Type the number of days of data to feed to the model ( one week maximum ): "))
    else:
     days = int(input("Type the number of days of data to feed to the model ( 3 days maximum ): "))  
   except:
      print("Invalid input")
      days = 0
try:
  if PRED_ALG == 1:
   prophet = trainProphetModel(days)

except:
   days = 0
   print("No values for selected time range, select a different one")


load_delta_db()
if len(DELTA_DB) == 0:
  while (t_time <= 0 or not isinstance(t_time, int)):
   try:
    t_time = int(input("Enter training time in minutes (A higher value will result in a more accurate threshold) : "))
   except:
    print("Invalid input. Please enter a valid number.")
  MIN_DELTA_N = t_time * 2
else:
 while (t_time < 0 or not isinstance(t_time, int)):
  try:
   t_time = int(input("Enter additional training time in minues (type 0 to skip) : "))
  except:
   print("Invalid input. Please enter a valid number.")
 MIN_DELTA_N = len(DELTA_DB) + (t_time * 2)
DELTA_N = MIN_DELTA_N 
valid_input = False
IMPROVE_ACC = False 
if len(DELTA_DB) > 0:
 
 while userChoice != "Y" and userChoice !="N":
  userChoice = input("Increase threadshold accuracy based on delta values' distribution? (will require additional training time) Y/N: ")
 
 if userChoice == "Y" or userChoice == "y":
    IMPROVE_ACC = True 
else:
   print("DB is empty, addional training will be needed")
   IMPROVE_ACC = True 
  


if  IMPROVE_ACC:
 while not valid_input and confidence_level == 0:
    try:
        print("\nNOTE: Accuracy is not guranteed with small amounts of delta values")
        confidence_level = float(input("Enter the  desired confidence level for anomaly detection: (in percentage): "))
        if confidence_level > 0 and confidence_level < 100:
            valid_input = True
        elif confidence_level == 100:
           print("Cannot have 100% accuracy")
        else:
            print("Please enter a valid confidence level between 0 and 99.")
    except  ValueError:
        print("Invalid input. Please enter a valid number.")

 z_value = get_z_value(confidence_level) 

if PRED_ALG == 1:
 schedule.every().hour.do(trainProphetModel,days)
schedule.every().hour.do(update_threshold,STD_DEV_TIMES)
start_http_server(8003)
print("\nPrometheus server started on port 8003")

addional_values_needed = 0
threshold = 0

if IMPROVE_ACC:
   DELTA_N = DELTA_N + round(get_required_delta_n(z_value))
print("Waiting for first value...")
try:
    while True:


        if len(DELTA_DB) >= MIN_DELTA_N:
         if not IMPROVE_ACC :    
           update_threshold(STD_DEV_TIMES)
           threshold_gauge.set(round(threshold))
         else: 
           addional_values_needed = DELTA_N - len(DELTA_DB)
           print("\nTRAINING IN PROGRESS (2) : Acquiring number of needed data for " + str(confidence_level) + "% accurate threshold ("+ str(round((TIME_DELTA * addional_values_needed)/60,1)) + " minutes left)")
           print("Current delta vaues: " + str(len(DELTA_DB)))
           print("Estimated addional delta values: " + str(addional_values_needed))
        else :
          print("\nTRAINING IN PROGRESS (1) : Collecting delta values (" +str(round(TIME_DELTA * (MIN_DELTA_N-len(DELTA_DB))/60,1)) + " minutes left)")
          
        if  IMPROVE_ACC and len(DELTA_DB) == DELTA_N:
          IMPROVE_ACC = False

        schedule.run_pending()
        # Chosing predicion alg
        if PRED_ALG == 1:
         forcast_value =  forecast(TIME_DELTA,prophet)
        else:
         holt = trainHoltWilterModel(days)
         forcast_value = forecastHoltWinter(holt,TIME_DELTA)
        # waiting for actual value
        time.sleep(TIME_DELTA)
        # reset anomaly gauge
        anomaly_gauge.set(float('nan')) 
        curr_value = getLastData()
        # computing delta
        delta = round(abs(int(curr_value) - (forcast_value)))
        delta_gauge.set(round(delta))
        print("--------------------------------")
        print("Predicted value: " + str(round(forcast_value)))
        print("Actual value: " + str(round(curr_value)))
        print("Delta: " + str(delta))
        if threshold != 0:
         print("Threshold: " + str(round(threshold)))
        else:
         print("Threshold: " + "N/A (Training still in progress)")
        if threshold != 0 and delta >  threshold:
           print("ANOMALY DETECTED - VALUE EXCEEDS THRESHOLD VALUE")
           anomaly_gauge.set(round(threshold))
        DELTA_DB.append(delta)

except KeyboardInterrupt:
   save_data()

