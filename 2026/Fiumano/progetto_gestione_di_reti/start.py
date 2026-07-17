import subprocess
import requests
import argparse
import re
import os
import json
import logging
from flask import Flask, request
import flask.cli
from datetime import datetime

app = Flask(__name__)   # creates web server using Flask
flask.cli.show_server_banner = lambda *args: None # disables the default Flask startup banner
logging.getLogger("werkzeug").disabled = True  # disables the default Flask request logging to keep the console output clean


def start_processes(prometheus_dir, node_exporter_dir, alertmanager_dir):
    # checks if Prometheus, Node Exporter, and Alertmanager are running, and starts them if they are not.
    processes = []
    os.makedirs("logs", exist_ok=True)
    try:
        response = requests.get("http://localhost:9090")
        if response.status_code == 200:
            print("Prometheus is already running.")
        else:
            print(f"Prometheus responded with {response.status_code}...")
    except requests.exceptions.ConnectionError:
        print("Prometheus is not running. Starting Prometheus...")
        processes.append(subprocess.Popen(
            ["./prometheus", "--config.file=prometheus.yml"],
            cwd=prometheus_dir,
            stdout=open(os.path.join("logs", "prometheus.log"), "w"),
            stderr=subprocess.STDOUT
        ))  # start Prometheus in the background and redirect its output to a log file

    try:
        response = requests.get("http://localhost:9100/metrics")
        if response.status_code == 200:
            print("Node Exporter is already running.")
        else:
            print(f"Node Exporter responded with {response.status_code}...")
    except requests.exceptions.ConnectionError:
        print("Node Exporter is not running. Starting Node Exporter...")
        processes.append(subprocess.Popen(
            ["./node_exporter"],
            cwd=node_exporter_dir,
            stdout=open(os.path.join("logs", "node_exporter.log"), "w"),
            stderr=subprocess.STDOUT
        ))  # start Node Exporter in the background and redirect its output to a log file

    try:
        response = requests.get("http://localhost:9093")
        if response.status_code == 200:
            print("Alertmanager is already running.")
        else:
            print(f"Alertmanager responded with {response.status_code}...")
    except requests.exceptions.ConnectionError:
        print("Alertmanager is not running. Starting Alertmanager...")
        processes.append(subprocess.Popen(
            ["./alertmanager", "--config.file=alertmanager.yml"],
            cwd=alertmanager_dir,
            stdout=open(os.path.join("logs", "alertmanager.log"), "w"),
            stderr=subprocess.STDOUT
        ))  # start Alertmanager in the background and redirect its output to a log file
    return processes


def set_prometheus_datasource(grafana_user, grafana_password):
    # Creates the Prometheus datasource in Grafana if it does not already exist.
    payload = {
        "name": "Prometheus",
        "type": "prometheus",
        "uid": "ffnnp3zgqyz28d",
        "url": "http://localhost:9090",
        "access": "proxy",
        "isDefault": True
    }
    response = requests.post(
        "http://localhost:3000/api/datasources",
        json=payload,
        auth=(grafana_user, grafana_password)
    )
    if response.status_code == 200:
        print("Prometheus datasource created.")
    elif response.status_code == 409:
        print("Prometheus datasource already exists.")
    else:
        raise RuntimeError(
            f"Datasource creation failed: {response.status_code} {response.text}"
        )


def upload_dashboard(dashboard_path, grafana_user, grafana_password):
    # Uploads the Grafana dashboard through the Grafana HTTP API.
    with open(dashboard_path, "r") as f:
        dashboard = json.load(f)

    # Ensures that Grafana creates a new dashboard instead of updating an existing one with the same ID.
    dashboard["id"] = None

    payload = {
        "dashboard": dashboard,
        "overwrite": True,
        "folderId": 0
    }

    response = requests.post(
        "http://localhost:3000/api/dashboards/db",
        json=payload,
        auth=(grafana_user, grafana_password)
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Dashboard upload failed: {response.status_code} {response.text}"
        )

    response_data = response.json()
    dashboard_url = "http://localhost:3000" + response_data.get("url", "")
    print(f"Dashboard uploaded successfully: {dashboard_url}")


@app.post("/")  # calls this function when an alert is received at the root URL ("/") via a POST request
def receive_alert():
    payload = request.json  # request is a Flask object that represents the incoming HTTP request (not the library).
    for alert in payload.get("alerts", []):
        labels = alert.get("labels", {})
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
        annotations = alert.get("annotations", {})
        print(f"[{timestamp}] [{alert.get('status')}] {labels.get('alertname')}")
        print(f"severity: {labels.get('severity')}")
        print(f"summary: {annotations.get('summary')}")
        print(f"description: {annotations.get('description')}")
        print()  # prints a blank line for better readability

    return "ok", 200  # returns a simple response to acknowledge that the alert was received successfully


def start_server(processes):
    try:
        app.run(host="127.0.0.1", port=5001, use_reloader=False)    # silence Flask logs
    except KeyboardInterrupt:
        print("Shutting down...")
        for p in processes:
            p.terminate()  # gracefully terminate the subprocesses (Prometheus, Node Exporter, Alertmanager)

        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()  # force kill the subprocess if it doesn't terminate within the timeout period


def configure_device(dashboard_path, prometheus_dir, device):
    # Reads dashboard and alert rules as text because it uses regex to replace the device label.
    files_to_configure = [
        (dashboard_path, dashboard_path),
        (os.path.join(prometheus_dir, "alerts.yml"), os.path.join(prometheus_dir, "alerts.yml")),
    ]

    for input_path, output_path in files_to_configure:
        with open(input_path, "r") as f:
            content = f.read()

        content = re.sub(
            r'device=\\"[^\\"]+\\"',
            f'device=\\"{device}\\"',
            content
        )

        content = re.sub(
            r'device="[^"]+"',
            f'device="{device}"',
            content
        )

        with open(output_path, "w") as f:
            f.write(content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure and start the project.")

    parser.add_argument("--dashboard", help="Path of the Grafana dashboard JSON file.")
    parser.add_argument("--device", help="Network interface to monitor.")
    parser.add_argument("--prometheus-dir", help="Path to the Prometheus directory.", required=True)
    parser.add_argument("--node-exporter-dir", help="Path to the Node Exporter directory.", required=True)
    parser.add_argument("--alertmanager-dir", help="Path to the Alertmanager directory.", required=True)
    parser.add_argument("--grafana-user", default="admin", help="Grafana username.")
    parser.add_argument("--grafana-password", default="admin", help="Grafana password.")

    args = parser.parse_args()

    if args.dashboard and args.device:
        configure_device(args.dashboard, args.prometheus_dir, args.device)
        print(f"Configuration completed for device {args.device}.")
    elif args.dashboard or args.device:
        parser.error("--dashboard and --device must be provided together.")

    processes = start_processes(
        args.prometheus_dir,
        args.node_exporter_dir,
        args.alertmanager_dir
    )

    if args.dashboard and args.device:
        set_prometheus_datasource(args.grafana_user, args.grafana_password)
        upload_dashboard(args.dashboard, args.grafana_user, args.grafana_password)
        print("Dashboard configured and uploaded to Grafana which runs on http://localhost:3000.")

    
    print("All services started, Prometheus runs on http://localhost:9090, Node Exporter on http://localhost:9100/metrics, Alertmanager on http://localhost:9093, and the alert receiver on http://localhost:5001.")
    start_server(processes)
