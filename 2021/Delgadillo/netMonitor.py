#!/usr/bin/env python3
import argparse
import time
import os
import pandas as pd
import matplotlib.pyplot as plot
import statistics
import warnings
from datetime import datetime
from pandas.core import series
from speedtest import Speedtest
from statsmodels.tsa.api import SimpleExpSmoothing

DATA = './data'
GRAPHICS = './graphics'
LAST_ELEMENT = -1


''' legge le opzioni e gli argomenti passati da linea di comando '''

def parse_args():

    parser = argparse.ArgumentParser(prog="netMonitor.py")

    parser.add_argument("-t","--times", help="esegue uno speedtest <times> volte",
            type=int, metavar=('times'), default=7)
    parser.add_argument("-p","--period", help="indica il periodo in minuti con cui eseguire gli speedtest",
            type=int, metavar=('period'), default=3)
    parser.add_argument("-f","--forecast", help="esegue una previsione usando <alpha>",
            type=float, metavar=('alpha'), default=0.60)
    parser.add_argument("-v", "--verbose", help="stampa i risultati al termine dello script", action="store_true")
    parser.add_argument("-e", "--export", help="esporta i grafici e i dati raccolti", action="store_true")

    args = parser.parse_args()

    return args

'''----------------------------------------------------------------------------------------------'''

''' esegue lo speedtest sia in download e ritorna un dizionario contenente i risultati '''

def test():
    s = Speedtest()

    #ottengo il miglior server disponibile
    s.get_best_server()

    #eseguo lo speedtest
    s.download(threads=1)
    s.upload(threads=1)

    return s.results.dict()

'''----------------------------------------------------------------------------------------------'''

''' scrive i risultati di uno speedtest nella tabella measurement tramite il client di influxdb '''

def write_point(points, data):

    #salvo l'istante di scrittura
    local_time = datetime.now()

    #genero il punto da inserire nel db
    point = {
            "time": local_time,
            "download": data["download"]/1000000,
            "upload": data["upload"]/1000000,
            "ping": data["ping"]
            }

    points.append(point)

'''----------------------------------------------------------------------------------------------'''

''' esegue una query sul database e trasforma il risultato in un dataframe '''

def points2DataFrame(points, period):

    tmp_dataframe = pd.DataFrame(points)

    #trasformo la colonna contenente il tempo nell'indice del dataframe
    datetime_index = pd.DatetimeIndex(pd.to_datetime(tmp_dataframe["time"]).values)
    freq = str(period) + 't'
    dataframe = tmp_dataframe.set_index(datetime_index.to_period(freq=freq))

    #rimuovo la colonna del tempo
    dataframe.drop('time', axis=1, inplace=True)

    return dataframe

'''----------------------------------------------------------------------------------------------'''

''' esegue una previsione usando il Simple Exponential Smoothing '''

def ses(data, attribute, alpha):
    dataframe = pd.DataFrame(data[attribute])
    fit = SimpleExpSmoothing(dataframe).fit(smoothing_level=alpha, optimized=False)
    forecast = fit.forecast(1).rename('Simple Exp Smoothing')
    return forecast

'''----------------------------------------------------------------------------------------------'''

''' controlla che i valori letti rispettino l'intervallo previsto '''

def check_anomaly (attribute, point, forecast, threshold):
    if point>threshold:
        if attribute == 'ping' :
            # il valore misurato supera il massimo previsto
            print("Sembra che ci siano problemi di latenza:")
            print(f"\tValore previsto: %.3f ms" % forecast)
            print(f"\tValore massimo previsto: %.3f ms" % threshold)
            print(f"\tValore letto: %.3f ms" % point)
    elif point < threshold :
        if attribute == 'upload' or attribute == 'download':
            # il valore misurato è inferiore al minimo previsto
            print("Sembra che ci sia un problema in " + attribute)
            print(f"\tValore previsto: %.3f Mbps" % forecast)
            print(f"\tValore minimo previsto: %.3f Mbps" % threshold)
            print(f"\tValore letto: %.3f Mbps" % point)

'''----------------------------------------------------------------------------------------------'''

def create_graphs(data, attribute, alpha, period):

    #recupero i dati del test
    dataframe = pd.DataFrame(data[attribute])

    #genero il grafico
    dataframe.plot.line()

    #Simple Exponential Smoothing
    fit = SimpleExpSmoothing(dataframe).fit(smoothing_level=alpha, optimized=False)
    forecast = fit.forecast(1).rename('Simple Exp Smoothing')
    fit.fittedvalues.plot(style='--', marker='o', color='red')
    forecast.plot(style='--', marker='o', color='red', legend=True)
    plot.xlim(dataframe.index[0], datetime.fromtimestamp(time.time()+ period * (2*60)))

    #creo i grafici delle previsioni
    plot.xlabel('Time')
    if attribute=='ping':
        plot.ylabel('Ping (ms)')
    elif attribute=='download':
        plot.ylabel('Download (Mbps)')
    else:
        plot.ylabel('Upload (Mbps)')

    plot.grid(axis='both', which='both')
    plot.savefig(f'{GRAPHICS}/{attribute}.png', format='png')

'''----------------------------------------------------------------------------------------------'''

''' funzione principale '''

def main():
    #leggo i parametri passati da linea di comando e controlli i valori
    args = parse_args()

    times = args.times
    if times == 0:
        print('times deve essere diverso da 0')
        exit(-1)

    period = args.period
    if period < 3:
        print('period deve essere maggiore di 3')
        exit(-1)

    alpha = args.forecast
    if alpha > 1 or alpha < 0:
        print('alpha deve essere compreso tra 0 e 1')
        exit(-1)

    verbose = args.verbose
    export = args.export

    # inizializzo la lista per mantenere i risultati degli speedtest
    points = []

    # inizializzo le liste per mantenere le previsioni
    fcasts_upload = []
    fcasts_download = []
    fcasts_ping = []

    # inizializzo le soglie per il controllo delle anomalie
    threshold_upload = -1
    threshold_download = -1
    threshold_ping = float('inf')

    #eseguo i test
    warnings.simplefilter(action='ignore', category=FutureWarning)

    i=0
    while True:

        try:
            init_time = time.time()
            print('Avvio speedtest numero ' + str(i+1))
            results = test()
            print('Speedtest terminato')
            write_point(points, results)

            # controllo se ci sono anomalie
            if len(points) >= 3:
                check_anomaly('download', points[LAST_ELEMENT]['download'], fcasts_download[LAST_ELEMENT], threshold_download)
                check_anomaly('upload', points[LAST_ELEMENT]['upload'], fcasts_upload[LAST_ELEMENT], threshold_upload)
                check_anomaly('ping', points[LAST_ELEMENT]['ping'], fcasts_ping[LAST_ELEMENT], threshold_ping)

            # converto la lista in un dataframe
            dataframe = points2DataFrame(points, period)

            if 0 < i < times:
                # eseguo le previsioni
                fcasts_download.extend((ses(dataframe, 'download', alpha).to_list()))
                fcasts_ping.extend(ses(dataframe, 'ping', alpha).to_list())
                fcasts_upload.extend(ses(dataframe, 'upload', alpha).to_list())

                # aggiorno le soglie
                if (i > 1):
                    threshold_download = fcasts_download[LAST_ELEMENT] - (2 * statistics.stdev(fcasts_download))
                    threshold_upload = fcasts_upload[LAST_ELEMENT] - (2 * statistics.stdev(fcasts_upload))
                    threshold_ping = fcasts_ping[LAST_ELEMENT] + (2 * statistics.stdev(fcasts_ping))

            final_time = time.time()

            if (i == times-1):
                break

            time.sleep(period*60 - (final_time - init_time))
            i+=1

        except KeyboardInterrupt:
            print("\nTest interrotto.")
            break

    nTest = len(points)

    if nTest > 0 and (verbose or export) :
        dataframe = points2DataFrame(points, period)
        print()
        print(dataframe)

        if export:
            #creo le directory per i dati
            if not os.path.exists(DATA):
                os.makedirs(DATA)
            os.chdir(DATA)

            directory = datetime.now().strftime("%Y-%m-%d_%H.%M")
            os.makedirs(directory)
            os.chdir(directory)

            #esporto dati in csv
            dataframe.to_csv("./data.csv")

            if nTest == 1:
                print("Non sono stati eseguiti abbastanza test per poter generare i grafici")
                return
            #creo i grafici delle previsioni
            if not os.path.exists(GRAPHICS):
                os.makedirs(GRAPHICS)

            create_graphs(dataframe, 'ping', alpha, period)
            create_graphs(dataframe, 'download', alpha, period)
            create_graphs(dataframe, 'upload', alpha, period)

'''----------------------------------------------------------------------------------------------'''

if __name__ == '__main__':
    main()
