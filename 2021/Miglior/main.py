
from candle import Candle
from plotly_charts import plot_data

import pandas as pd
import stats_methods as sm
import rrdtool as rrd

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
    dataset.remove(None)
    candles = []
    time = start_time

    # analyze line chart and build a candle taking n. thickness points.
    while len(dataset) > thickness:
        vals = dataset[:thickness]
        dataset = dataset[thickness:]
        candles.append(Candle(time, vals[0], vals[-1], max(vals), min(vals)))
        time += step * thickness

    candles.append(Candle(time, dataset[0], dataset[-1], max(dataset), min(dataset)))
    return candles


def fetch_rrd_data(rrd_path):
    # Fetching first and last timestamp from RRD database
    first = rrd.first(DB)
    last = rrd.last(DB)

    res = rrd.fetch(rrd_path, "AVERAGE", "-e", str(last), '-s', str(first))
    start, end, step = res[0]
    ds = res[1]
    rows = res[2]

    print('*** NOTICE: RRD step is {}s, and selected candle step is {} -> each candle will represent {} minutes of data ***\n'.format(
        step,
        CANDLE_STEP,
        step*CANDLE_STEP/60)
    )

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


if __name__ == '__main__':

    # load configuration
    build_config()

    print('> fetching data from database...')

    start, end, step, ds, rows = fetch_rrd_data(DB)
    ds_rows = []

    for x in rows:
        ds_rows.append(x[DS_INDEX])

    # Building candles and creating pandas dataframe to analyze data.
    candles = build_candles(start, step, ds_rows, CANDLE_STEP)

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

    anomaly_df = pd.DataFrame(anomaly_list)
    plot_data(df, anomaly_df, QUANTILE, ADDRESS, PORT)

