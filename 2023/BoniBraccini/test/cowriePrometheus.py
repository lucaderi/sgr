import os
from prometheus_client import start_http_server, Summary, Gauge
import random
import time
import json
import subprocess

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')
LOGFILE = "/ctrl1/syncedLog.json"
orphan_counter = 0
live_counter = 0
LAST_LINE_FILE = './last_line_prom.txt'
LOGGED_CONNECTIONS = []
NEW_CONNECTIONS = []
PENDING_NEW_CONNECTIONS = []
PENDING_LOGGED_CONNECTIONS = []
STARTED = False

def get_last_line():
    try:
        with open(LAST_LINE_FILE, 'r') as file:
            last_line = file.read().strip()
    except OSError:
        last_line = ''
    return last_line


def update_last_line(last_line):
    with open(LAST_LINE_FILE, 'w') as file:
        file.write(last_line)

@REQUEST_TIME.time()
def collect_metrics():
    #Define temporary variables
    global LOGGED_CONNECTIONS
    global NEW_CONNECTIONS
    global PENDING_NEW_CONNECTIONS
    global PENDING_LOGGED_CONNECTIONS
    global STARTED


    TMP_DOWNLOADS = 0
    TMP_REFUSED = 0
    TMP_COMMANDS = 0
    LINEFLAG = 0
    LINENUMBER = 0
    #Gathering Cowrie log data (from data1.json rsync data)
    last_line = get_last_line()
    new_lines = []
    with open(LOGFILE, 'r') as log:
        lines = log.readlines()
        if not lines:
         print("Source file is empty...")
         return
        if not last_line or last_line+'\n' not in lines:
            update_last_line(lines[-1])
            new_lines = []
            for closed_session in PENDING_NEW_CONNECTIONS:
                if closed_session in NEW_CONNECTIONS:
                 NEW_CONNECTIONS.remove(closed_session)
                PENDING_NEW_CONNECTIONS = []
            for closed_session in PENDING_LOGGED_CONNECTIONS:
                    if closed_session in LOGGED_CONNECTIONS:
                     LOGGED_CONNECTIONS.remove(closed_session)
                    PENDING_LOGGED_CONNECTIONS = []
        else:
            last_line_index = lines.index(last_line+'\n')
            new_lines = lines[last_line_index+1:]
    for line in new_lines:
        if STARTED:
            try:
                log_line_json = json.loads(line)
            except:
                print("Parsing error on Line: " + line)
                # Extract the connections, downloads etc ...
            event_id = log_line_json['eventid']
            session = log_line_json['session']
            if event_id == "cowrie.session.connect" :
                if event_id not in NEW_CONNECTIONS:
                 NEW_CONNECTIONS.append(session)
                 print("New connection (" + str(len(NEW_CONNECTIONS)) + " total)")
            elif event_id == "cowrie.login.success" :
                if event_id not in LOGGED_CONNECTIONS:
                 LOGGED_CONNECTIONS.append(session)
                 print("New login connection  (" + str(len(LOGGED_CONNECTIONS)) + " total)")
            elif event_id == "cowrie.login.failed" :
                TMP_REFUSED += 1
                print("New refused connection  (" + str(TMP_REFUSED) + " total)")
            elif event_id == "cowrie.session.file_download":
                TMP_DOWNLOADS += 1
                print("New download connection  (" + str(TMP_DOWNLOADS) + " total)")
            elif event_id == "cowrie.command.input":
                TMP_COMMANDS += 1
                command = log_line_json['input']
                print("New command run  (" + str(TMP_COMMANDS) + " total)")
                if 'curl' in command or 'wget' in command or 'http' in command:
                 TMP_DOWNLOADS += 1
                 print("New download command (" + str(TMP_DOWNLOADS) + " total)")

            elif event_id == "cowrie.session.closed":

             if session in NEW_CONNECTIONS:
                print("Connection closed")
                PENDING_NEW_CONNECTIONS.append(session)

             if session in LOGGED_CONNECTIONS:
                print("Logged in connection closed")
                PENDING_LOGGED_CONNECTIONS.append(session)



    if new_lines:
        update_last_line(new_lines[-1])
        print("Parsed "+ str(len(new_lines)) +" new lines")
    else:
        print("No new lines to parse.")



    print("TOTAL CONNECTIONS: " + str(len(NEW_CONNECTIONS)))
    print("ACTIVE CONNECTIONS: " + str(len(LOGGED_CONNECTIONS )))
    print("REFUSED CONNECTIONS: " + str(TMP_REFUSED ))
    print("DOWNLOADS: " + str(TMP_DOWNLOADS))
    print("COMMANDS: " + str(TMP_COMMANDS))

    connections.set(len(NEW_CONNECTIONS))
    accepted_connections.set(len(LOGGED_CONNECTIONS))
    commands.set(TMP_COMMANDS)
    refused_connections.set(TMP_REFUSED)
    downloads.set(TMP_DOWNLOADS)

    if len(PENDING_NEW_CONNECTIONS) > 0:
     print("CLEANING UP " + str(len(PENDING_NEW_CONNECTIONS)) + " closed  connections")

    for closed_session in PENDING_NEW_CONNECTIONS:
     if closed_session in NEW_CONNECTIONS:
      NEW_CONNECTIONS.remove(closed_session)
    PENDING_NEW_CONNECTIONS = []

    if len(PENDING_LOGGED_CONNECTIONS) > 0:
     print("CLEANING UP " + str(len(PENDING_LOGGED_CONNECTIONS)) + " closed logged connections")


    for closed_session in PENDING_LOGGED_CONNECTIONS:
        if closed_session in LOGGED_CONNECTIONS:
         LOGGED_CONNECTIONS.remove(closed_session)
        PENDING_LOGGED_CONNECTIONS = []

    try:
        #Get vm stats from virtualbox manager
        command = "VBoxManage metrics query HON1 Guest/CPU/Load/User,Guest/CPU/Load/Kernel,Guest/RAM/Usage/Total,Net/Rate/Tx,Net/Rate/Rx | awk '{print $3}'"
        output = subprocess.check_output(command, shell=True).decode("utf-8").strip().split("\n")
        network_rx = int(output[2])
        network_tx = int(output[3])
        cpu_user_load = float(output[4].rstrip('%'))
        cpu_kernel_load = float(output[5].rstrip('%'))
        ram_usage = int(output[6])
        VM_CPU_User.set(cpu_user_load)
        VM_CPU_Kernel.set(cpu_kernel_load)
        VM_RAM_Usage.set(ram_usage)
        VM_NET_TX.set(network_tx)
        VM_NET_RX.set(network_rx)
    except:
       if not STARTED:
        print("Cannot get VirtualManage Metrics! Are you in testing mode? ")
    if not STARTED:
      print("Initializing... Metrics will be counted from the next iteration")
      STARTED = True


if __name__ == '__main__':
    #Scrape interval of the log file
    SCRAPE_INTERVAL = 30
    #Setting Cowrie Gauges
    connections = Gauge("Cowrie_SSH_connections","The number of new ssh connections to Cowrie")
    downloads = Gauge("Cowrie_downloads","The number of new downloaded files")
    accepted_connections = Gauge("Cowrie_SSH_accepted_connections", "The number of successfull connections via ssh")
    refused_connections = Gauge("Cowrie_SSH_refused_connections", "The number of refused connections via ssh")
    commands = Gauge("Cowrire_SSH_commands","The  number of SSH commands")

    #Setting virtualbox VM Gauges
    VM_CPU_Kernel = Gauge("VM_CPU_Kernel","The CPU usage of the kernel in the Honeypot VM")
    VM_CPU_User = Gauge("VM_CPU_User","The CPU usage of the user in the Honeypot VM")
    VM_RAM_Usage = Gauge("VM_RAM_Usage","The RAM usage (KB) of the Honeypot VM")
    VM_NET_RX = Gauge("VM_NET_RX","The network interface RX (B/s) of the Honeypot VM")
    VM_NET_TX = Gauge("VM_NET_TX","The network interface TX (B/s) of the Honeypot VM")


    # Avvia il server Prometheus
    start_http_server(8001)

    print("Prometheus server started on port 8001")

    while True:
        try:
            collect_metrics()
            time.sleep(SCRAPE_INTERVAL)
        except KeyboardInterrupt:
            print("Stopping server")
            break


