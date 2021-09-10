import tkinter as tk
from tkinter import messagebox
import utilities
from matplotlib import pylab as plt
import smoothing
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import (FigureCanvasTkAgg)


# Clear window from all element in the interface
def clear_frame(window):
    list_elements = window.pack_slaves()
    for element in list_elements:
        element.destroy()


# Check if alpha is between 0 and 1
def check_alpha(textbox):
    str_alpha = textbox.get("1.0", 'end-1c')
    try:
        alfa = float(str_alpha)
        if alfa < 0 or alfa > 1:
            messagebox.showerror(title="Error", message="Alfa not valid")
            return -1
        else:
            return alfa
    except ValueError:
        messagebox.showerror(title="Error", message="Alfa  not valid")
        return -1


# Check if beta is between 0 and 1
def check_beta(textbox):
    str_beta = textbox.get("1.0", 'end-1c')
    try:
        beta = float(str_beta)
        if beta < 0 or beta > 1:
            messagebox.showerror(title="Error", message="Beta not valid")
            return -1
        else:
            return beta
    except ValueError:
        messagebox.showerror(title="Error", message="Beta not valid")
        return -1


# Clear the page and put initial component on the window
def back_initial_page(window):
    clear_frame(window)
    setup_gui_input_source(window)


# Function that call single smoothing
def setup_plot(all_dates, all_times, dates, result, window, n_prediction):
    fig = Figure(figsize=(9, 5), dpi=100)
    plt_figure = fig.add_subplot(111)
    plt_figure.plot(all_dates, all_times, "-b", label="Original Data")
    if n_prediction == 1:
        plt_figure.plot(dates, result, "-r", label="Single Smoothing")
    else:
        plt_figure.plot(dates, result, "-r", label="Double Smoothing")
    plt_figure.axvline(dates[int((len(all_dates) / 4 * 3)) - n_prediction], 0, c="g", label='Start predictions')
    plt_figure.legend(loc="upper right")
    canvas = FigureCanvasTkAgg(fig, master=window)  # A tk.DrawingArea.
    canvas.draw()
    list_elements = window.pack_slaves()
    if len(list_elements) > 10:
        list_elements[10].destroy()  # delete old canvas
        list_elements[11].destroy()
        list_elements[12].destroy()
    return canvas


def call_single_smoothing(data, window, options, list_metrics, textbox):
    alfa = check_alpha(textbox)
    if alfa == -1:
        return
    index_metric = list_metrics.index(options.get(), 0, len(list_metrics))  # get index of metric in the array
    values = data['data']['result'][index_metric]['values']  # get values from data read
    all_dates = []
    all_times = []
    for timestamp, value in values:
        all_dates.append(timestamp)  # insert data in arrays
        all_times.append(float(value))
    len_training = int(len(data['data']['result'][index_metric]['values']) / 4 * 3)  # 2/3 dati di training
    dates = []
    times = []
    for i in range(len_training+1):
        dates.append(values[i][0])
        times.append(float(values[i][1]))
    dates.append(values[len_training][0])
    result = smoothing.exponential_smoothing(times, alfa)
    canvas = setup_plot(all_dates, all_times, dates, result, window, 1)
    canvas.get_tk_widget().pack()
    times.append(all_times[len(times)])
    sse = smoothing.sse(times, result)
    sse_string = 'SSE: ' + str(sse)
    label_sse = tk.Label(window, text=sse_string, width=25)
    label_sse.pack()
    button_back = tk.Button(window, height=1, width=20, text="Back", command=lambda: back_initial_page(window))
    button_back.pack()


# Function that call double smoothing
def call_double_smoothing(data, window, options, list_metrics, textbox_alfa, textbox_beta):
    alfa = check_alpha(textbox_alfa)
    if alfa == -1:
        return
    beta = check_beta(textbox_beta)
    if beta == -1:
        return
    index_metric = list_metrics.index(options.get(), 0, len(list_metrics))
    values = data['data']['result'][index_metric]['values']
    all_dates = []
    all_times = []
    for timestamp, value in values:
        all_dates.append(timestamp)  # insert data in arrays
        all_times.append(float(value))
    len_training = int(len(data['data']['result'][index_metric]['values']) / 4 * 3)  # 2/3 dati di training
    dates = []
    times = []
    for i in range(len_training + 1):
        dates.append(values[i][0])
        times.append(float(values[i][1]))
    plt.plot(all_dates, all_times)
    dates.append(values[len_training][0])
    dates.append(values[len_training+1][0])
    result = smoothing.double_exponential_smoothing(times, alfa, beta)
    canvas = setup_plot(all_dates, all_times, dates, result, window, 2)
    canvas.get_tk_widget().pack()
    times.append(all_times[len(times)])
    times.append(all_times[len(times)+1])
    sse = smoothing.sse(times, result)
    sse_string = 'SSE: ' + str(sse)
    label_sse = tk.Label(window, text=sse_string, width=25)
    label_sse.pack()
    button_back = tk.Button(window, height=1, width=20, text="Back", command=lambda: back_initial_page(window))
    button_back.pack()


# Function that setup component for the analysis interface
def setup_gui_input_analysis(window, data):
    list_metrics = utilities.get_metrics(data)
    window.geometry("950x800")  # Size of the window
    window.title("Smoothing Data Series")  # Adding a title
    options = tk.StringVar(window)
    options.set(list_metrics[0])  # default value
    label_input_metric = tk.Label(window, text='Metric', width=25)
    label_input_metric.pack()
    om1 = tk.OptionMenu(window, options, *list_metrics)
    om1.pack()
    label_input_alfasingle = tk.Label(window, text='Alfa', width=25)
    label_input_alfasingle.pack()
    textbox_alfasingle = tk.Text(window, height=1, width=20)
    textbox_alfasingle.pack()
    button_single = tk.Button(window, height=1, width=20, text="Single Smoothing", command=lambda: call_single_smoothing(data, window, options, list_metrics, textbox_alfasingle))
    button_single.pack()
    label_input_alfadouble = tk.Label(window, text='Alfa', width=25)
    label_input_alfadouble.pack()
    textbox_alfadouble = tk.Text(window, height=1, width=20)
    textbox_alfadouble.pack()
    label_input_betadouble = tk.Label(window, text='Beta', width=25)
    label_input_betadouble.pack()
    textbox_betadouble = tk.Text(window, height=1, width=20)
    textbox_betadouble.pack()
    button_double = tk.Button(window, height=1, width=20, text="Double Smoothing", command=lambda: call_double_smoothing(data, window, options, list_metrics, textbox_alfadouble, textbox_betadouble))
    button_double.pack()


# Function that read call read from json or prometheus
def retrieve_input_source(options, textbox, window):
    choice = options.get()
    if choice == 'JSON':
        filename = textbox.get("1.0", 'end-1c')
        data = utilities.read_json_file(filename)
        if not data:
            messagebox.showerror(title="Error", message="File Name not valid")
        else:
            clear_frame(window)
            setup_gui_input_analysis(window, data)
    else:
        data = utilities.read_from_prometheus()
        if not data:
            messagebox.showerror(title="Error", message="Prometheus not launched")
        else:
            clear_frame(window)
            setup_gui_input_analysis(window, data)
    print(choice)


# Function that setup gui for the start page
def setup_gui_input_source(window):
    window.geometry("600x200")  # Size of the window
    window.title("Smoothing Data Series")  # Adding a title
    options = tk.StringVar(window)
    options.set("JSON")  # default value
    label_input_series = tk.Label(window, text='Input Data Series', width=25)
    label_input_series.pack()
    om1 = tk.OptionMenu(window, options, "JSON", "Prometheus")
    om1.pack()
    label_input_filename = tk.Label(window, text='Input File Name If JSON', width=15)
    label_input_filename.pack()
    textbox = tk.Text(window, height=1, width=20)
    textbox.pack()
    button_commit = tk.Button(window, height=1, width=20, text="Commit", command=lambda: retrieve_input_source(options, textbox, window))
    button_commit.pack()
    window.mainloop()


# Create the window
def create_window():
    window = tk.Tk()
    setup_gui_input_source(window)
