import matplotlib.pyplot as plt
import matplotlib.dates as md
from datetime import timedelta

# Custom print and input
def inputyellow(txt):
    cend = '\33[0m'
    cyellow = '\33[33m'
    r = input(cyellow + txt + cend)
    return r


def printyellow(txt):
    cend = '\33[0m'
    cyellow = '\33[33m'
    print(cyellow + txt + cend)


def printgreen(txt):
    cend = '\33[0m'
    cgreen = '\33[32m'
    print(cgreen + txt + cend)


def plotRSI(rsi, dates, title=None):
    plt.gca().xaxis.set_major_formatter(md.DateFormatter('%H:%M'))
    plt.plot(dates[0:len(rsi)], rsi[0:len(rsi)], label="RSI")
    plt.xticks(rotation=45)
    plt.xlabel("Time")
    plt.ylabel("")
    plt.legend(loc="upper left")
    if not (title is None):
        plt.title(title)
    plt.get_current_fig_manager().window.maximize()
    plt.show()


def plotSDE(values, dates, predictions, title=None):
    plt.gca().xaxis.set_major_formatter(md.DateFormatter('%H:%M'))
    plt.plot(dates[0:len(values)], values, label="Values")
    plt.plot(dates, predictions, '--', label="Predictions")
    plt.xticks(rotation=45)
    plt.xlabel("Time")
    plt.ylabel("KBytes")
    plt.legend(loc="upper left")
    if not (title is None):
        plt.title(title)
    plt.get_current_fig_manager().window.maximize()
    plt.show()


# Plotting
def plot(values, dates, predictions=None, upperbound=None, lowerbound=None, rsi=None, title=None):
    plt.gca().xaxis.set_major_formatter(md.DateFormatter('%H:%M'))

    plt.plot(dates[0:len(values)], values, label="Values")

    if not(predictions is None):
        plt.plot(dates[len(values):], predictions[len(values):], '--', label="Predictions")

    if not (upperbound is None):
        plt.plot(dates[0:len(values)], upperbound[0:len(values)], 'g:', label="Upper bound")
        anomalous = []
        for i in range(len(values)):
            if (values[i] > upperbound[i]):
                plt.axvspan(dates[i]-timedelta(minutes=2, seconds=30), dates[i]+timedelta(minutes=2, seconds=30), facecolor='r', alpha=0.25)
                anomalous.append(values[i])

    if not (lowerbound is None):
        plt.plot(dates[0:len(values)], lowerbound[0:len(values)], 'r:', label="Lower bound")
        anomalous = []
        for i in range(len(values)):
            if (values[i] < lowerbound[i]):
                plt.axvspan(dates[i]-timedelta(minutes=2, seconds=30), dates[i]+timedelta(minutes=2, seconds=30), facecolor='r', alpha=0.25)
                anomalous.append(values[i])

    if not (rsi is None):
        plt.plot(dates[0:len(values)], rsi[0:len(values)], label="RSI")

    plt.xticks(rotation=45)
    plt.xlabel("Time")
    plt.ylabel("KBytes")
    plt.legend(loc="upper left")

    if not (title is None):
        plt.title(title)
    plt.get_current_fig_manager().window.maximize()
    plt.show()
