import time

from candle import Candle
import plotly_charts as charts

import pandas as pd
import stats_methods as sm
import rrdtool as rrd

import threading

import json

# anomaly detection tuning defaults
CANDLE_STEP = 3
DS_INDEX = 0
ANOMALY_THRESHOLD = 2
ALPHA = 0.6
BETA = 0.5
DELTA = 2
METHOD = 'double'
QUANTILE = 0.95
USE_QUANTILE = False
DB = "../rrd/db.rrd"
ADDRESS = '127.0.0.1'
PORT = 5678
WAIT = 20
DEPTH = 20


def build_config():

    global CANDLE_STEP
    global DS_INDEX
    global ANOMALY_THRESHOLD
    global ALPHA
    global BETA
    global DELTA
    global QUANTILE
    global USE_QUANTILE
    global DB
    global METHOD
    global ADDRESS
    global PORT
    global WAIT

    with open(file='./config.json', mode='r') as config:
        conf = json.load(config)
        try:
            CANDLE_STEP = conf['step']
            DS_INDEX = conf['rrd-ds-index']
            ANOMALY_THRESHOLD = conf['threshold']
            ALPHA = conf['alpha']
            BETA = conf['beta']
            DELTA = conf['delta']
            QUANTILE = conf['quantile']
            USE_QUANTILE = conf['use-quantile']
            DB = conf['rrd-path']
            METHOD = conf['method']
            ADDRESS = conf['local-server']
            PORT = conf['port']
            WAIT = conf['update-interval']

        except KeyError:
            print('*** NOTICE: some configuration values were not found, using defaults. ***')


# detect anomalies based on how many abnormal parameters have been detected
# e.g. detected volume, open, close anomaly for the same timestamp
def detect_anomaly(row, volume: bool, open: bool, close: bool):

    a = []
    if (row['open'] > row['op_confidence_upper_band'] or row['open'] < row['op_confidence_lower_band']) and open:
        a.append('open')

    if (row['close'] > row['close_confidence_upper_band'] or row['close'] < row['close_confidence_lower_band']) and close:
        a.append('close')

    if (row['volume'] > row['vol_confidence_upper_band'] or row['volume'] < row['vol_confidence_lower_band']) and volume:
        a.append('volume')

    return a


def build_candles(start_time: int, step: int, dataset: list, thickness: int) -> []:

    # remove none elements
    dataset = list(filter(lambda a: a is not None, dataset))

    c = []
    t = start_time

    # analyze line chart and build a candle taking n. thickness points.
    while len(dataset) >= thickness:
        vals = dataset[:thickness]
        dataset = dataset[thickness:]
        c.append(Candle(t, vals[0], vals[-1], max(vals), min(vals)))
        t += step * thickness

    # return built candles and last candle timestamp.
    return c, t


def fetch_rrd_data(rrd_path, last, first):
    # Fetching first and last timestamp from RRD database

    res = rrd.fetch(rrd_path, "AVERAGE", "-e", str(last), '-s', str(first))
    start, end, step = res[0]
    ds = res[1]
    rows = res[2]

    return start, end, step, ds, rows


# Compute some forecast data for candlestick represented time series in pandas dataframe df.
# each row of the dataset represents a candle in the candlestick, having the following format:
#
#            | DateIndex | open value | close value | max value | min value | volume
#
# this function will add forecast values forecasting to df, using exponential moving average methods.


def forecast_data(df, method, alpha, beta, delta):
    if method == 'simple':
        df['open_forecast'] = sm.simple_exponential_smoothing(df['open'], alpha=alpha)
        df['close_forecast'] = sm.simple_exponential_smoothing(df['close'], alpha=alpha)
        df['volume_forecast'] = sm.simple_exponential_smoothing(df['volume'], alpha=alpha)

    elif method == 'double':
        df['open_forecast'] = sm.double_exponential_smoothing(df['open'], alpha=alpha, beta=beta)
        df['close_forecast'] = sm.double_exponential_smoothing(df['close'], alpha=alpha, beta=beta)
        df['volume_forecast'] = sm.double_exponential_smoothing(df['volume'], alpha=alpha, beta=beta)

    # compute std and fill df with confidence bands
    # setting ddof to 0 in order to calculate empirical variance (numpy behaviour)

    open_std = (abs(df['open_forecast'] - df['open'])).std(ddof=0)
    close_std = (abs(df['close_forecast'] - df['close'])).std(ddof=0)
    volume_std = (abs(df['volume_forecast'] - df['volume'])).std(ddof=0)

    df['op_confidence_upper_band'] = [val + delta * open_std for val in df['open_forecast']]
    df['op_confidence_lower_band'] = [val - delta * open_std for val in df['open_forecast']]
    df['vol_confidence_upper_band'] = [val + delta * volume_std for val in df['volume_forecast']]
    df['vol_confidence_lower_band'] = [val - delta * volume_std for val in df['volume_forecast']]
    df['close_confidence_upper_band'] = [val + delta * close_std for val in df['close_forecast']]
    df['close_confidence_lower_band'] = [val - delta * close_std for val in df['close_forecast']]


def analyze_data(df, quantiles):
    print('> analyzing data...\n')

    anomaly_list = []

    print('----------------- ANALYSIS REPORT -----------------\n')

    for index, row in df.iterrows():

        # Adding column anomaly_type to dataframe to spot and get anomalies in frame.
        a = detect_anomaly(row=row, volume=True, open=True, close=True)
        data = {
            'date': row['date'],
            'volume': row['volume'],
            'open': row['open'],
            'close': row['close'],
        }

        count = 0

        # Check for percentile outliers
        for s in a:
            if row[s] > quantiles[s]:
                count += 1

        # combine outliers and forecasting anomalies
        # count > 0 means that at least one parameter (open, close, volume)
        # for the considered row is out of selected percentile.
        #
        # len(a) > threshold means that at least THRESHOLD params are out of
        # forecasted values of delta * sigma

        if len(a) >= ANOMALY_THRESHOLD and (count > 0 and USE_QUANTILE):
            anomaly_list.append(data)
            print('> Anomaly found @ {}:'.format(row['date']))
            print('\t-> %s' % ', '.join(map(str, a)), end=' ')
            print('are out of {} sigma in respect of exponential forecasting'.format(DELTA))
            print('\t-> {} params were out of {}th percentile'.format(count, QUANTILE * 100))

        # We're not using percentile combined with forecasting
        elif len(a) >= ANOMALY_THRESHOLD and not USE_QUANTILE:
            anomaly_list.append(data)
            print('> Anomaly found @ {}:'.format(row['date']))
            print('\t-> %s' % ', '.join(map(str, a)), end=' ')
            print('are out of {} sigma in respect of exponential forecasting'.format(DELTA))

    print('\n> {} anomalies were found during analysis.\n'.format(len(anomaly_list)))

    print('---------------------------------------------------\n\n')

    return anomaly_list


if __name__ == '__main__':

    # load configuration
    build_config()

    # Build anomaly dataframe to store anomalies data.

    anomaly_df = pd.DataFrame()

    print('> fetching data from database...')

    # first, read the whole database to synchronize with current time.

    start, end, step, ds, rows = fetch_rrd_data(DB, str(rrd.last(DB)), str(rrd.first(DB)))
    ds_rows = []
    candles = []

    for x in rows:
        ds_rows.append(x[DS_INDEX])

    # Building candles and creating pandas dataframe to analyze data.
    candles, start = build_candles(start, step, ds_rows, CANDLE_STEP)

    # Build pandas dataframe
    df = pd.DataFrame.from_records(s.to_dict() for s in candles)

    quantiles = {
        'volume': df['volume'].quantile(QUANTILE),
        'open': df['open'].quantile(QUANTILE),
        'close': df['close'].quantile(QUANTILE)
    }

    print('> creating forecast model for fetched data...')
    forecast_data(df, method='double', alpha=ALPHA, beta=BETA, delta=DELTA)
    # Look for anomalies with forecasting
    anomaly_df = pd.DataFrame.from_records(analyze_data(df, quantiles))

    # enter while loop: fetching data will begin from last read value (end)

    ds_rows = []
    candles = []

    # start live chart daemon server
    dash_thread = threading.Thread(target=charts.begin, args=(ADDRESS, PORT, df))
    dash_thread.setDaemon(True)
    dash_thread.start()

    # Start while loop to forecast live-streamed data from rrd source:
    # How does it work:
    # keep trace of last candle timestamp, then fetch data starting from that timestamp until now.
    # Candles building algorithm has been improved: function builds exactly n candles and n is the great
    # integer such that n mod thickness = 0
    # after building candles, the last timestamp is saved again and the other rows are dropped
    # (not more than thickness - 1 rows are discarded, and it's acceptinable)
    # new candles are now analyzed: forecasting is based on previous _DEPTH_ candles.
    # if new anomalies are detected, they're added to anomaly df in order to be printed.
    # if it's necessary to compute quantiles, candles are added to original df and new quantiles are generated.

    while True:
        start, end, step, ds, rows = fetch_rrd_data(DB, 'now', str(start))

        for x in rows:
            ds_rows.append(x[DS_INDEX])

        candles, start = build_candles(start, step, ds_rows, CANDLE_STEP)

        update_df = pd.DataFrame()

        # upload some old values to make better forecasting on new data
        # the bigger is the old dataset, the better forecasting.
        update_df = pd.concat([df.tail(DEPTH), update_df])
        update_df = pd.concat([update_df, pd.DataFrame.from_records(s.to_dict() for s in candles)], ignore_index=True)

        # make predictions only on new dataframe.
        forecast_data(update_df, method='double', alpha=ALPHA, beta=BETA, delta=DELTA)

        # just update new candles: tail functions assures that only the candles are added to the df, avoiding
        # duplicates and loops inside data.
        # it's not strictly necessary to merge old df with new ones; it's needed only for charting purposes.
        # the script also needs all the dataframe to compute quantiles.
        # callback is needed since concat function changes reference to mutable object df -> we need to pass it to
        # the charting module to refresh df reference.

        update_df = update_df.tail(len(candles))
        df = pd.concat([df, update_df], ignore_index=True)

        # here we are
        if USE_QUANTILE:
            quantiles['volume'] = df['volume'].quantile(QUANTILE)
            quantiles['open'] = df['open'].quantile(QUANTILE)
            quantiles['close'] = df['close'].quantile(QUANTILE)

        else:
            df = update_df
            anomaly_df = pd.DataFrame.from_records(analyze_data(df, quantiles))

        analyze_data(update_df, quantiles)

        charts.df_callback(df, anomaly_df, quantiles)
        ds_rows.clear()
        candles.clear()
        time.sleep(WAIT)

