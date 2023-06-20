import os
from prometheus_client import start_http_server, Summary, Gauge
import random
import time
import json

LAST_LINE_FILE = './last_line_promDion.txt'
STARTED = False
LOGFILE = "/ctrl1/syncedLogDion.json"



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

def collect_metrics():
    #Define temporary variables
    global STARTED
    TMP_CONNECTIONS_HTTP = 0
    TMP_DOWNLOADS = 0
    TMP_CONNECTIONS_SMB = 0
    TMP_CONNECTIONS_FTP = 0
    LINENUMBER = 0
    last_line = get_last_line()
    new_lines = []
    with open(LOGFILE, 'r') as log:
        lines = log.readlines()
        if not lines:
         print("Source file is empty...")
         return
        if not last_line or last_line+'\n' not in lines:
            new_lines = lines
        else:
            last_line_index = lines.index(last_line+'\n')
            new_lines = lines[last_line_index+1:]

        # Each line of the log file is a json object

    for line in new_lines:
         if STARTED:
             try:
                log_line_json = json.loads(line)
             except:
              print("Parsing error on Line: " + LINENUMBER)
            # Extract the connections, downloads etc ...
             connection_type = log_line_json['connection_type']
             connection_protocol = log_line_json['connection_protocol']
             event_id = log_line_json['eventid']
             if connection_type == "accept":
                if event_id == "download":
                    #new file download
                    TMP_DOWNLOADS += 1
                elif connection_protocol == "httpd" :
                    #New http connection
                    TMP_CONNECTIONS_HTTP += 1
                elif connection_protocol == "smbd" :
                    #new samba connection
                    TMP_CONNECTIONS_SMB += 1
                elif connection_protocol == "ftpd" :
                    TMP_CONNECTIONS_FTP += 1



    if new_lines:
        update_last_line(new_lines[-1])
        print("Parsed "+ str(len(new_lines)) +" new lines")
    else:
        print("No new lines to parse.")

    if not STARTED:
      STARTED = True
      print("INITIALIZING...")


    print("HTTP CONNECTIONS: " + str(TMP_CONNECTIONS_HTTP))
    print("DOWNLOADS: " + str(TMP_DOWNLOADS))
    print("FTP CONNECTIONS: " + str(TMP_CONNECTIONS_FTP))
    print("SMB CONNECTIONS: " + str(TMP_CONNECTIONS_SMB))
    dionaea_connections_http.set(TMP_CONNECTIONS_HTTP)
    dionaea_downloads.set(TMP_DOWNLOADS)
    dionaea_connections_ftp.set(TMP_CONNECTIONS_FTP)
    dionaea_connections_smb.set(TMP_CONNECTIONS_SMB)


if __name__ == '__main__':
    #Scrape interval of the log file
    SCRAPE_INTERVAL = 30
    #Setting Dionaea Gauges
    dionaea_connections_http = Gauge("Dionaea_HTTP_connections","The number of new http connections to Dionaea")
    dionaea_connections_ftp = Gauge("Dionaea_FTP_connections","The number of new ftp connections to Dionaea")
    dionaea_connections_smb = Gauge("Dionaea_SMB_connections","The number of new smb connections to Dionaea")
    dionaea_downloads = Gauge("Dionaea_downloads","The number of new downloaded files on Dionaea honeypot")

    # Avvia il server Prometheus
    start_http_server(8002)

    print("Prometheus server started on port 8002")

    while True:
        try:
            collect_metrics()
            time.sleep(SCRAPE_INTERVAL)
        except KeyboardInterrupt:
            print("Stopping server")
            break
