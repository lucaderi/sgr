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
    gruppi = {}
    inizio_primo_gruppo = None
    gruppo_corrente = 1
    ip_segnalati_precedenti = set()  # IP segnalati nel gruppo precedente

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

                # set l'orario del primo gruppo
                if inizio_primo_gruppo is None:
                    inizio_primo_gruppo = timestamp_dt_italian
                    gruppi[gruppo_corrente] = []

                # get numero del gruppo corrente
                delta = timestamp_dt_italian - inizio_primo_gruppo
                gruppo_corrente = (delta // timedelta(minutes=5)) + 1

                # Aggiunge la riga al gruppo appropriato
                if gruppo_corrente not in gruppi:
                    gruppi[gruppo_corrente] = []
                gruppi[gruppo_corrente].append({
                    "ip": ip,
                    "timestamp": timestamp_dt_italian,
                    "request": request,
                    "status": int(status)
                })

    # Analisi dei gruppi
    with open(output_file, "a") as out_file:
        for gruppo, righe in sorted(gruppi.items()):
            sospetti = set()
            fallimenti = {}
            richieste_malevole = {}

            for log in righe:
                ip = log["ip"]
                request = log["request"]
                status = log["status"]

                # check SQL Injection
                if re.search(r"(?:' OR |UNION|SELECT|--)", request, re.IGNORECASE):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

                # check URL sospetto
                if re.search(r"GET /(\.|config|backup|env|passwd)", request, re.IGNORECASE):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

                # Tentativi di login falliti consecutivi
                if status >= 400:
                    if ip not in fallimenti:
                        fallimenti[ip] = 0
                    fallimenti[ip] += 1
                else:
                    fallimenti[ip] = 0

                # check tentativi di login da IP fuori dall'Italia
                if "login" in request and not is_ip_from_italy(ip, reader):
                    richieste_malevole[ip] = richieste_malevole.get(ip, 0) + 1

            # Segnala IP con richieste malevole e condizioni specifiche
            for ip, count in richieste_malevole.items():
                if count >= 3 or ip in ip_segnalati_precedenti:
                    sospetti.add(ip)

            # Aggiunge IP con più fallimenti consecutivi
            for ip, count in fallimenti.items():
                if count >= 3:
                    sospetti.add(ip)

            # Scrive gli IP sospetti nel file di output
            if sospetti:
                out_file.write(f"Gruppo {gruppo} (file: {file_name}): IP sospetti rilevati - {', '.join(sospetti)}\n")
                ip_segnalati_precedenti = sospetti  # Aggiorna i segnalati per il gruppo successivo


# Funzione per ordinare e analizzare i file di log
def analyze_log_files_in_directory(directory, reader, output_file):
    # Recupera tutti i file nella cartella e ordina per data di modifica
    log_files = sorted(
        [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))],
        key=os.path.getmtime
    )

    # Analisi file di log
    for log_file in log_files:
        print(f"Analizzando il file: {log_file}")
        analyze_log(log_file, reader, output_file)


def main():
    # Creazione del parser per i parametri da linea di comando
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
