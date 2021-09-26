import json
import requests
import time


def read_json_file(filename):
    try:
        with open(filename) as json_file:
            data = json.load(json_file)
        return data
    except FileNotFoundError:
        return []


def read_from_prometheus(start_time):
    try:
        end_time = time.time()
        response = requests.get('http://localhost:9090/api/v1/query_range?query=probe_http_duration_seconds&start=' +start_time.__str__() + '&end=' + end_time.__str__() + '&step=5s')
        data = json.loads(response.text)
        if len(data['data']['result'][0]['values']) >= 2:
            start_time = end_time
    except requests.exceptions.ConnectionError:
        data = []
    return data, start_time


def get_metrics(data):
    list_metrics = []
    for r in data['data']['result']:
        list_metrics.append(r['metric']['phase'])
    return list_metrics


def average(values):
    sum = 0
    for i in range(1, len(values)):
        sum += values[i]
    return sum/len(values)


def get_index_metric(list_metrics, metric_selected):
    for i in range(len(list_metrics)):
        if metric_selected == list_metrics[i]:
            return i