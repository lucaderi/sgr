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


def read_from_prometheus():
    try:
        runtime_json = requests.get(
            "http://localhost:9090/api/v1/status/runtimeinfo")  # ottengo le informazioni di runtime da prometheus
        runtime_info = json.loads(runtime_json.text)  # parsing informazioni
        start_time = runtime_info['data']['startTime']  # tempo da cui inizierò a richiedere dati
        end_time = time.time()
        response = requests.get(
            'http://localhost:9090/api/v1/query_range?query=probe_http_duration_seconds&start=' +
            start_time + '&end=' + end_time.__str__() + '&step=10m')
        data = json.loads(response.text)
    except requests.exceptions.ConnectionError:
        data = []
    return data


def get_metrics(data):
    list_metrics = []
    for r in data['data']['result']:
        list_metrics.append(r['metric']['phase'])
    return list_metrics
