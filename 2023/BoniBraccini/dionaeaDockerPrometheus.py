from prometheus_client import start_http_server, Gauge
from datetime import datetime
import time
import json
import subprocess
import re

LOGFILE = "dionaea/json1/dionaea.json."
LAST_LINE_FILE = './lastlinepromDion.txt' 
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

def collect_metrics(date):
    #Define temporary variables
    global STARTED
    TMP_CONNECTIONS_HTTP = 0
    TMP_DOWNLOADS = 0
    TMP_CONNECTIONS_SMB = 0
    TMP_CONNECTIONS_FTP = 0
    LINENUMBER = 0
    last_line = get_last_line()
    new_lines = []
    todayFile = LOGFILE + date
    with open(todayFile, 'r') as log:
        lines = log.readlines()
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

    #Get Container stats from docker manager
    try:
     command = 'docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" dionaea'
     process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
     output, _ = process.communicate()
     cpu_load = re.findall(r'dionaea\s+(\d+\.\d+)%', output)[0]
     print(cpu_load)
     mem_usage = re.findall(r'dionaea\s+\d+\.\d+%.*?(\d+\.\d+\w+)\s+/\s+(\d+\.\d+\w+)', output)[0]
     mem_used, mem_limit = mem_usage
     mem_usage_mib = convert_to_megabytes(mem_used)

     print("CPU USAGE " + str(cpu_load))
     print("RAM USAGE " + str(mem_usage_mib))
    # Set the VM values to the Prometheus Gauges
     DIONAEA_DOCKER_CPU_Load.set(cpu_load)
     DIONAEA_DOCKER_RAM_Usage.set(mem_usage_mib)

    except Exception as e:
     print("Error requesting stats from Docker!")
     print(e)



def convert_to_megabytes(mem_usage):
    match = re.match(r'(\d+\.\d+)(\w+)', mem_usage)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        if unit == 'KiB':
            value /= 1024
        elif unit == 'MiB':
            pass
        elif unit == 'GiB':
            value *= 1024
        return value
    return None

if __name__ == '__main__':
    #Scrape interval of the log file
    SCRAPE_INTERVAL = 30
    #Setting Cowrie Gauges
    dionaea_connections_http = Gauge("Dionaea_HTTP_connections","The number of new http connections to Dionaea")
    dionaea_connections_ftp = Gauge("Dionaea_FTP_connections","The number of new ftp connections to Dionaea")
    dionaea_connections_smb = Gauge("Dionaea_SMB_connections","The number of new smb connections to Dionaea")
    dionaea_downloads = Gauge("Dionaea_downloads","The number of new downloaded files on Dionaea honeypot")
    #Setting Cowrie Gauges
    DIONAEA_DOCKER_CPU_Load = Gauge("DIONAEA_DOCKER_CPU_Load","Dionaea docker cpu usage")
    DIONAEA_DOCKER_RAM_Usage = Gauge("DIONAEA_DOCKER_RAM_Usage","Dionaea docker ram usage")


    # Avvia il server Prometheus
    start_http_server(8002)

    print("Prometheus server started on port 8002")

    while True:
        try:
            current_date = datetime.now().date()
            formatted_date = current_date.strftime("%Y-%m-%d")
            collect_metrics(formatted_date)
            time.sleep(SCRAPE_INTERVAL)
        except KeyboardInterrupt:
            print("Stopping server")
            break

