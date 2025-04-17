
import subprocess
import statistics
import re
import json
import time
import platform

# Funzione per caricare i paesi dal file JSON
def load_country_from_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        return data['country']
# Funzione per caricare i parametri dal file JSON
def load_parameters_from_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        return data['parameters']


# Carica i paesi dal file JSON
country = load_country_from_json('country.json')
# Carica i parametri dal file JSON
params = load_parameters_from_json('parameters.json')

# Parametri
PING_COUNT = params["PING_COUNT"]
PING_TIMEOUT = params["PING_TIMEOUT"]
PING_INTERVAL = params["PING_INTERVAL"]
OUTLIER_FACTOR = params["OUTLIER_FACTOR"]

# Determina il sistema operativo per l'esecuzione del comando ping
is_windows = platform.system().lower().startswith("win")

# Regex per Linux e Windows del comando ping
rtt_regex_linux = re.compile(r'time=([\d.]+) ms', re.IGNORECASE)        # significa cattura + numeri decimali
rtt_regex_windows = re.compile(r'durata[=<]([\d]+)ms', re.IGNORECASE)   # in windows può essere durata = oppure durata <
# Durata da modificare in base alla lingua

# Risultati finali
rtt_results = {}

# Funzione per filtrare i valori troppo lontani dalla media
def filter_outliers(all_rtts, mean_rtt, stddev_rtt):
    # Calcolo i bound moltiplicati per un fattore esterno
    lower_bound = mean_rtt - OUTLIER_FACTOR * stddev_rtt
    upper_bound = mean_rtt + OUTLIER_FACTOR * stddev_rtt
    # Ritorno solo quelli nei bound
    return [rtt for rtt in all_rtts if lower_bound <= rtt <= upper_bound]

for country_code, country_host in country.items():
    # Tutti gli rtt per un paese
    all_rtts = []
    print(f"Pinging country: {country_code}...")

    # NTP Pool Project mette a disposizione server da 0 a 3
    for i in range(4):  
        # Sintassi server NTP Pool
        host = f"{i}.{country_host}.pool.ntp.org"
        print(f"  Pinging {host}")
        # _ serve a dire che non ci interessa tenere traccia dell'indice
        for _ in range(PING_COUNT):
            
            try:
                if is_windows:
                    cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), host]
                else:
                    cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), host]

                # Prende l'output della console e lo trasforma da byte in testo
                result = subprocess.run( cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True )
                output = result.stdout
                print(output)
                match = (rtt_regex_windows if is_windows else rtt_regex_linux).search(output)
                #print(match)
                if match:
                    # dove group(0) restituisce l'intera stringa mentre group(1) restituisce la porzione tra parentesi tonde
                    rtt = float(match.group(1))
                    all_rtts.append(rtt)
            except Exception as e:
                print(f"Error pinging {host}: {e}")

            time.sleep(PING_INTERVAL)

    # Se ho trovato qualcosa per quel paese
    if all_rtts:
        # Calcolo una media e deviazione standard iniziali
        mean_rtt = statistics.mean(all_rtts)
        stddev_rtt = statistics.stdev(all_rtts) if len(all_rtts) > 1 else 0.0
        
        # Filtra i valori anomali
        filtered_rtts = filter_outliers(all_rtts, mean_rtt, stddev_rtt)

        # Se il filtraggio non ha rimosso tutti i valori
        if filtered_rtts:
            mean_rtt_filtered = statistics.mean(filtered_rtts)
            stddev_rtt_filtered = statistics.stdev(filtered_rtts) if len(filtered_rtts) > 1 else 0.0
            # Arrotondo la media e deviazione standard a 6 cifre decimali poiché in Wireshark sono misurate con questa approssimazione
            rtt_results[country_code] = {
                "mean": round(mean_rtt_filtered, 6),
                "stddev": round(stddev_rtt_filtered, 6)
            }
        else:
            print(f"No valid RTTs for {country_code} after filtering outliers")
    else:
        print(f"No successful pings for {country_code}")

# Scrittura dei risultati in un file di testo
with open("ntp_rtt_stats.txt", "w") as f:
    for country_code, stats in rtt_results.items():
        # Scrivi in formato "US,144.77,15.61"
        f.write(f"{country_code},{stats['mean']},{stats['stddev']}\n")
