import os
from prometheus_client import start_http_server, Summary, Gauge
import time
import json
from collections import deque
import pickle



LAST_LINE_FILE = './last_line_promDion.txt'
STARTED = False
LOGFILE = "./syncedLogDion.json"
INTERVALS_IN_WEEK = 201600 # it will store values for a week maximum
CONNECTIONS_HTTP_VALUES = deque(maxlen=INTERVALS_IN_WEEK)
CONNECTIONS_SMB_VALUES = deque(maxlen=INTERVALS_IN_WEEK)
CONNECTIONS_FTP_VALUES = deque(maxlen=INTERVALS_IN_WEEK)
DOWNLOADS_VALUES = deque(maxlen=INTERVALS_IN_WEEK)


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
    global CONNECTIONS_HTTP_VALUES
    global CONNECTIONS_SMB_VALUES
    global CONNECTIONS_FTP_VALUES
    global DOWNLOADS_VALUES

    
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

    ## Try to read old values from backup
    if not STARTED:
     ftp = "connections_ftp_BACKUP.pkl"
     smb = "connections_smb_BACKUP.pkl"
     http = "connections_http_BACKUP.pkl"
     downloads = "downloads_BACKUP.pkl"

     try:
      with open(ftp, "rb") as file:
       CONNECTIONS_FTP_VALUES = pickle.load(file)
       print("FTP values history restored")
     except :
      print("No old values found for FTP connections")

     try:
        with open(smb, "rb") as file:
            CONNECTIONS_SMB_VALUES = pickle.load(file)
            print("SMB values history restored")
     except:
      print("No old values found for SMB connections")

     try:
      with open(http, "rb") as file:
       CONNECTIONS_HTTP_VALUES = pickle.load(file)
       print("HTTP values history restored")
     except :
      print("No old values found for HTTP connections")

     try:
        with open(downloads, "rb") as file:
            DOWNLOADS_VALUES = pickle.load(file)
            print("Downloads values history restored")
     except:
      print("No old values found for downloads")

    

    if new_lines:
        update_last_line(new_lines[-1])
        print("Parsed "+ str(len(new_lines)) +" new lines")
    else:
        print("No new lines to parse.")

    if not STARTED:
      print("Collector started, metrics will be recorded every 30 seconds...")
      STARTED = True

    if STARTED:

        print("\n---CURRENT VALUES---")
        print("HTTP CONNECTIONS: " + str(TMP_CONNECTIONS_HTTP))
        print("FTP CONNECTIONS: " + str(TMP_CONNECTIONS_FTP ))
        print("SMB CONNECTIONS: : " + str(TMP_CONNECTIONS_SMB))
        print("DOWNLOADS " + str(TMP_DOWNLOADS))
        print("---------------------\n")
        dionaea_connections_http.set(TMP_CONNECTIONS_HTTP)
        dionaea_downloads.set(TMP_DOWNLOADS)
        dionaea_connections_ftp.set(TMP_CONNECTIONS_FTP)
        dionaea_connections_smb.set(TMP_CONNECTIONS_SMB)


        #add values to values queue (for z-score calc)
        CONNECTIONS_HTTP_VALUES.append(TMP_CONNECTIONS_HTTP)
        CONNECTIONS_SMB_VALUES.append(TMP_CONNECTIONS_SMB)
        CONNECTIONS_FTP_VALUES.append(TMP_CONNECTIONS_FTP)
        DOWNLOADS_VALUES.append(TMP_DOWNLOADS)
        '''
        print("HHTP connection values:\n")
        for value in CONNECTIONS_HTTP_VALUES:
            print(value)

        print("SMB connection values:\n")
        for value in CONNECTIONS_SMB_VALUES:
         print(value)


        print("FTP connection values:\n")
        for value in CONNECTIONS_FTP_VALUES:
         print(value)

        print("Downloads values:\n")
        for value in DOWNLOADS_VALUES:
         print(value)
        '''
    #update zscore values 
        z_score_http = calculate_z_score(CONNECTIONS_HTTP_VALUES,TMP_CONNECTIONS_HTTP)
        z_score_smb= calculate_z_score(CONNECTIONS_SMB_VALUES,TMP_CONNECTIONS_SMB)
        z_score_ftp = calculate_z_score(CONNECTIONS_FTP_VALUES,TMP_CONNECTIONS_FTP)
        z_score_downloads = calculate_z_score(DOWNLOADS_VALUES,TMP_DOWNLOADS)

        print("\n-------Z-SCORES------------")
        print("HTTP Connections: "+ str(z_score_http))
        print("FTP Connections: "+ str(z_score_ftp))
        print("SMB Connections: "+ str(z_score_smb))
        print("Downloads: "+ str(z_score_downloads))
        print("--------------------------\n")
    
        # set z-score gauges
        connections_http_zscore.set(TMP_CONNECTIONS_HTTP)
        connections_ftp_zscore.set(TMP_CONNECTIONS_FTP)
        connections_smb_zscore.set(TMP_CONNECTIONS_SMB)
        downloads_zscore.set(TMP_DOWNLOADS)



def calculate_z_score(q, actual_value):
    total = 0
    len = 0
    for value in q:
        total += value
        len = len + 1
    
    mean = float(total) / len
    #print("Sum:" + str(total))   
    #print("Len:" + str(len))   
    #print("Current mean: " + str(mean))
    variance = float(sum((x - mean) ** 2 for x in q) / len)
    #print("Current variance: " + str(variance))
    if variance == 0:
        z_score = 0 
    else:
        std_dev =     float(variance ** 0.5)
        z_score = float((actual_value - mean) / std_dev)
    return z_score


   
def save_data():
    ftp = "connections_ftp_BACKUP.pkl"
    smb = "connections_smb_BACKUP.pkl"
    http = "connections_http_BACKUP.pkl"
    downloads = "downloads_BACKUP.pkl"

    with open(ftp, "wb") as file:
        pickle.dump(CONNECTIONS_FTP_VALUES, file)
        print("Connections saved")   

    with open(smb, "wb") as file:
        pickle.dump(CONNECTIONS_SMB_VALUES, file)
        print("Accepted connection saved") 

    with open(http, "wb") as file:
            pickle.dump(CONNECTIONS_FTP_VALUES, file)
            print("Run commands saved")

    with open(downloads, "wb") as file:
            pickle.dump(DOWNLOADS_VALUES, file)
            print("Downloads saved")   

if __name__ == '__main__':
    #Scrape interval of the log file
    SCRAPE_INTERVAL = 30
    #Setting Dionaea Gauges
    dionaea_connections_http = Gauge("Dionaea_HTTP_connections","The number of new http connections to Dionaea")
    dionaea_connections_ftp = Gauge("Dionaea_FTP_connections","The number of new ftp connections to Dionaea")
    dionaea_connections_smb = Gauge("Dionaea_SMB_connections","The number of new smb connections to Dionaea")
    dionaea_downloads = Gauge("Dionaea_downloads","The number of new downloaded files on Dionaea honeypot")
    connections_http_zscore = Gauge("Dionaea_HTTP_connections_zscore","Z-score value of http connections")
    connections_ftp_zscore = Gauge("Dionaea_SMB_connections_zscore","Z-score value of ftp connetions")
    connections_smb_zscore = Gauge("Dionaea_SMB_connections_smb_zscore","Z-score value of smb connetions")
    downloads_zscore = Gauge("Dionaea_downloads_zscore","Z-score value of downloads ")


    # Avvia il server Prometheus
    start_http_server(8002)
    SCRAPE_INTERVAL = 30
    print("Prometheus server started on port 8002")

    while True:
        try:
            collect_metrics()
            time.sleep(SCRAPE_INTERVAL)
        except KeyboardInterrupt:
            print("Saving data...")
            save_data()
            print("Done")
            print("Stopping server")
            break