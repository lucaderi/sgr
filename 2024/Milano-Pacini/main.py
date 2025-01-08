import argparse
import re
import os
from datetime import datetime, timedelta
import pytz
import geoip2.database

# Regex per estrarre l'IP e il timestamp
log_pattern = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] \"(?P<request>[^\"]+)\" (?P<status>\d+)"

italian_tz = pytz.timezone("Europe/Rome")


def is_ip_from_italy(ip, reader):
    try:
        response = reader.country(ip)
        return response.country.iso_code == "IT"
    except geoip2.errors.AddressNotFoundError:
        print(f"L'IP {ip} non è stato trovato nel database.")
        return False
    except Exception as e:
        print(f"Errore durante la geolocalizzazione dell'IP {ip}: {e}")
        return False


def analyze_log(file_name, reader, output_file):
    time_windows = {}
    inizio_primo_window = None
    current_window = 1
    ip_segnalati_precedenti = set()  # IP segnalati nel window precedente

    with open(file_name, "r") as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                ip = match.group("ip")
                timestamp_str = match.group("timestamp")
                request = match.group("request")
                status = match.group("status")

                # Conversione del timestamp in un oggetto datetime
                timestamp_dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                timestamp_dt_italian = timestamp_dt.astimezone(italian_tz)

                # set l'orario del primo window
                if inizio_primo_window is None:
                    inizio_primo_window = timestamp_dt_italian
                    time_windows[current_window] = {
                        "start_time": inizio_primo_window,
                        "end_time": inizio_primo_window + timedelta(minutes=5),
                        "logs": []
                    }

                # get numero del window corrente
                delta = timestamp_dt_italian - inizio_primo_window
                current_window = (delta // timedelta(minutes=5)) + 1

                # aggiunge la riga del log alla finestra temporale adeguata
                if current_window not in time_windows:
                    start_time = inizio_primo_window + timedelta(minutes=(current_window - 1) * 5)
                    end_time = start_time + timedelta(minutes=5)
                    time_windows[current_window] = {
                        "start_time": start_time,
                        "end_time": end_time,
                        "logs": []
                    }

                time_windows[current_window]["logs"].append({
                    "ip": ip,
                    "timestamp": timestamp_dt_italian,
                    "request": request,
                    "status": int(status)
                })

    # analisi della finestra temporale attuale
    with open(output_file, "a") as out_file:
        for window, data in sorted(time_windows.items()):
            sospetti = set()
            fallimenti = {}
            richieste_malevole = {}

            for log in data["logs"]:
                ip = log["ip"]
                request = log["request"]
                status = log["status"]

                # check SQL Injection
                if re.search(r"(?:' OR |UNION|SELECT|--)", request, re.IGNORECASE):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

                # check URL sospetto
                if re.search(r"GET /(\.|config|backup|env|passwd)", request, re.IGNORECASE):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

                # tentativi di login falliti consecutivi
                if status >= 400:
                    if ip not in fallimenti:
                        fallimenti[ip] = 0
                    fallimenti[ip] += 1
                else:
                    fallimenti[ip] = 0

                # check tentativi di login da IP fuori dall'Italia
                if "login" in request and not is_ip_from_italy(ip, reader):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

            # segnalazione IP con richieste malevole
            for ip, count in richieste_malevole.items():
                if count >= 3 or ip in ip_segnalati_precedenti:
                    sospetti.add(ip)

            # add IP con più fallimenti consecutivi
            for ip, count in fallimenti.items():
                if count >= 3:
                    sospetti.add(ip)

            # write IP sospetti nel file di output.txt
            if sospetti:
                out_file.write(f"\n=== Periodo: {data['start_time'].strftime('%Y-%m-%d %H:%M:%S')} - {data['end_time'].strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                out_file.write(f"IP sospetti rilevati: {', '.join(sospetti)}\n")
                ip_segnalati_precedenti = sospetti  # ip sospetti tenuti in memoria per il window successivo


def analyze_log_files_in_directory(directory, reader, output_file):
    with open(output_file, "a") as out_file:
        start_time = datetime.now().astimezone(italian_tz)
        out_file.write("\n" + "=" * 50 + "\n")
        out_file.write(f"Inizio analisi: {start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        out_file.write("=" * 50 + "\n")

    # get tutti i file nella cartella e ordina per data di modifica
    log_files = sorted(
        [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))],
        key=os.path.getmtime
    )

    for log_file in log_files:
        print(f"Analizzando il file: {log_file}")
        analyze_log(log_file, reader, output_file)

    with open(output_file, "a") as out_file:
        end_time = datetime.now().astimezone(italian_tz)
        out_file.write("\n" + "=" * 50 + "\n")
        out_file.write(f"Fine analisi: {end_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        out_file.write("=" * 50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Analizza i file di log per attività sospette.")
    parser.add_argument(
        "log_directory",
        help="Cartella contenente i file di log da analizzare"
    )
    parser.add_argument(
        "db_path",
        help="Percorso del file del database GeoIP"
    )
    parser.add_argument(
        "output_file",
        help="Percorso del file di output per gli IP sospetti"
    )

    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"Errore: il file del database {args.db_path} non esiste.")
        return

    reader = geoip2.database.Reader(args.db_path)
    analyze_log_files_in_directory(args.log_directory, reader, args.output_file)
    reader.close()

if __name__ == "__main__":
    main()
