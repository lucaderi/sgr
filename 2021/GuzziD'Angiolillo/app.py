import base64
import time
from io import BytesIO

from flask import Flask, request, render_template
import numpy as np

import smoothing
import utilities
from matplotlib.figure import Figure

app = Flask(__name__)
data = []
list_metrics = []
live = 0
start_time = time.time()
ub = []
lb = []
file_name = ''


@app.route('/')
def welcome():  # put application's code here
    return app.send_static_file('welcome.html')


@app.route('/smoothing')
def smoothing_gui():
    global data, list_metrics, live, start_time, ub, lb, file_name
    arguments = request.args
    if arguments.get('selection') == 'JSON':
        file_name = arguments.get('file_name')
        data = utilities.read_json_file(arguments.get('file_name'))
        if not data:
            live = 0
            return app.send_static_file('error_filename_not_found.html')
    else:
        live = 1
        data, temp = utilities.read_from_prometheus(start_time)
        if not data:
            return app.send_static_file('error_prometheus_not_started.html')
    list_metrics = utilities.get_metrics(data)
    ub, lb = [], []
    return render_template('smoothing_data.html', metrics=list_metrics, plot=None)


@app.route('/single_smoothing')
def single_smoothing_entry():
    global start_time, data
    if live:
        data, start_time = utilities.read_from_prometheus(start_time)
        template = single_smoothing(request.args, 'smoothing_live.html')
    else:
        template = single_smoothing(request.args, 'smoothing_not_live.html')
    return template


@app.route('/double_smoothing')
def double_smoothing_entry():
    global start_time, data
    if live:
        data, start_time = utilities.read_from_prometheus(start_time)
        template = double_smoothing(request.args, 'smoothing_live.html')
    else:
        template = double_smoothing(request.args, 'smoothing_not_live.html')
    return template


def single_smoothing(arguments, page):
    global ub, lb
    alfa = float(arguments.get('alfa'))
    metric_selected = arguments.get('metric')
    index_metric = utilities.get_index_metric(list_metrics, metric_selected)
    pairs = data['data']['result'][index_metric]['values']
    timestamps, values = split_time_values(pairs)
    correct = True
    if ub != [] and lb != []:
        correct = check_last_prevision(timestamps, values, 1)
    results = smoothing.exponential_smoothing(values, alfa)
    timestamp_prevision = []
    if len(timestamps) < 2:
        print('time')
        print(timestamps)
        return render_template('smoothing_live.html', metrics=list_metrics, plot=None, alfa=alfa, beta=None,
                               metric=None, correct=correct, number_capture=len(timestamps))
    timestamp_prevision.append(timestamps[-1] + timestamps[-1] - timestamps[-2])
    if live == 0:
        lb, ub = calculate_bounds(values, results, 1)
    plot = setup_plot(timestamps, values, timestamp_prevision, results, 1)
    lb, ub = calculate_bounds(values, results, 1)
    return compose_page_html(plot, page, alfa, None, metric_selected, correct)


def double_smoothing(arguments, page):
    global ub, lb
    alfa = float(arguments.get('alfa'))
    beta = float(arguments.get('beta'))
    metric_selected = arguments.get('metric')
    index_metric = utilities.get_index_metric(list_metrics, metric_selected)
    pairs = data['data']['result'][index_metric]['values']
    timestamps, values = split_time_values(pairs)
    correct = True
    if ub != [] and lb != [] and live == 1:
        correct = check_last_prevision(timestamps, values, 2)
    results = smoothing.double_exponential_smoothing(values, alfa, beta)
    if len(timestamps) < 2:
        return render_template('smoothing_live.html', metrics=list_metrics, plot=None, alfa=alfa, beta=beta, metric=None, correct=correct, number_capture=len(timestamps))
    timestamp_prevision = []
    timestamp_prevision.append(timestamps[-1] + timestamps[-1] - timestamps[-2])
    timestamp_prevision.append(timestamp_prevision[-1] + timestamp_prevision[-1] - timestamps[-1])
    if live == 0:
        lb, ub = calculate_bounds(values, results, 2)
    plot = setup_plot(timestamps, values, timestamp_prevision, results, 2)
    lb, ub = calculate_bounds(values, results, 2)
    return compose_page_html(plot, page, alfa, beta, metric_selected, correct)


def check_last_prevision(timestamps, value, num_prevision):
    global ub, lb
    if num_prevision == 1:
        if timestamps[0] != start_time:
            return lb[-1] < value[0] < ub[-1]
        else:
            return lb[-1] < value[1] < ub[-1]
    else:
        if timestamps[0] != start_time:
            return lb[-2] < value[0] < ub[-2] and lb[-1] < value[1] < ub[-1]
        else:
            return lb[-2] < value[1] < ub[-2] and lb[-1] < value[2] < ub[-1]


def compose_page_html(plot, page, alfa, beta, metric, correct):
    buf = BytesIO()
    plot.savefig(buf, format='png')
    buf.seek(0)
    buffer = b''.join(buf)
    b2 = base64.b64encode(buffer)
    plot2 = b2.decode('utf-8')
    if beta is None:
        return render_template(page, metrics=list_metrics, smoothing='Single', plot=plot2, alfa=alfa, beta=beta,
                               metric=metric, correct=correct, number_capture=3, file_name=file_name)
    else:
        return render_template(page, metrics=list_metrics, smoothing='Double', plot=plot2, alfa=alfa, beta=beta,
                               metric=metric, correct=correct, number_capture=3, file_name=file_name)


def compose_select():
    str_select = '<select>'
    list_m = utilities.get_metrics(data)
    for i in range(len(list_m)):
        str_select += '<option value="' + list_m[i] + '">' + list_m[i] + '</option>'
    str_select += '</select>'
    return str_select


# Function that call single smoothing
def setup_plot(all_dates, all_times, timestamp_prevision, value_prevision, n_prediction):
    fig = Figure(figsize=(11, 7), dpi=100)
    plt_figure = fig.add_subplot(111)
    plt_figure.plot(all_dates, all_times, "-b", label="Original Data")
    if n_prediction == 1:
        plt_figure.grid()
        plt_figure.plot(timestamp_prevision[-1], value_prevision[-1], marker="o", markersize=6, markeredgecolor="red",
                        markerfacecolor="red")
        if ub != [] and lb != []:
            if live == 1:
                if start_time != all_dates[0]:
                    plt_figure.plot(all_dates[0], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[0], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")

                else:
                    plt_figure.plot(all_dates[1], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[1], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
            else:
                plt_figure.plot(timestamp_prevision[-1], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")
                plt_figure.plot(timestamp_prevision[-1], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")

    else:
        plt_figure.grid()
        plt_figure.plot(timestamp_prevision[-2], value_prevision[-2], marker="o", markersize=6, markeredgecolor="red",
                        markerfacecolor="red")
        plt_figure.plot(timestamp_prevision[-1], value_prevision[-1], marker="o", markersize=6, markeredgecolor="red",
                        markerfacecolor="red")
        if ub != [] and lb != []:
            if live == 1:
                if start_time != all_dates[0]:
                    plt_figure.plot(all_dates[0], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[0], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[1], ub[1], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[1], lb[1], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                else:
                    plt_figure.plot(all_dates[1], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[1], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[2], ub[1], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
                    plt_figure.plot(all_dates[2], lb[1], marker="o", markersize=6, markeredgecolor="green",
                                    markerfacecolor="green")
            else:
                plt_figure.plot(timestamp_prevision[-2], ub[0], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")
                plt_figure.plot(timestamp_prevision[-2], lb[0], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")
                plt_figure.plot(timestamp_prevision[-1], ub[1], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")
                plt_figure.plot(timestamp_prevision[-1], lb[1], marker="o", markersize=6, markeredgecolor="green",
                                markerfacecolor="green")
    return fig


def calculate_bounds(values, results, smooth):
    upper, lower = [], []
    if smooth == 1:
        dev = np.std(values)
        upper.clear()
        lower.clear()
        upper.append(results[-1] + dev)
        lower.append(results[-1] - dev)
    else:
        dev = np.std(values)
        upper.clear()
        lower.clear()
        upper.append(results[-2] + dev)
        upper.append(results[-1] + dev)
        lower.append(results[-2] - dev)
        lower.append(results[-1] - dev)
    return lower, upper


def split_time_values(pairs):
    timestamps, values = [], []
    for timestamp, value in pairs:
        timestamps.append(timestamp)  # insert data in arrays
        values.append(float(value))
    return timestamps, values


if __name__ == '__main__':
    app.run()
