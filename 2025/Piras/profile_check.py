import csv
import json
from collections import Counter

def load_profiles(path="profiles.json"):
    with open(path) as f:
        data = json.load(f)
    # Se data è un dict già nel formato {"ip": {...}}, lo restituiamo direttamente
    return data

def check_behavior(csv_file, profiles_file="profiles.json"):
    print("[*] Verifica coerenza comportamento IP...")

    # Parsing file CSV corrente
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        current = {}
        for row in reader:
            ip = row['SrcIP']
            fc = row['FunctionCode']
            if ip not in current:
                current[ip] = Counter()
            current[ip][fc] += 1

    profiles = load_profiles(profiles_file)

    for ip, fc_count in current.items():
        prof = profiles.get(ip)
        if not prof:
            print(f"[!] Nuovo IP rilevato: {ip}")
            continue

        # Convertiamo la lista salvata in set per confronto
        stored_fc = set(prof["function_codes"])
        current_fc = set(fc_count.keys())

        extra = current_fc - stored_fc
        missing = stored_fc - current_fc

        if extra:
            print(f"[!] IP {ip} usa nuovi function code non previsti: {', '.join(sorted(extra))}")
        if missing:
            print(f"[-] IP {ip} non ha più usato questi codici: {', '.join(sorted(missing))}")

    print("[✓] Verifica completata.")
    
    
def main():
    check_behavior("parsed_data.csv", "profiles.json")
    
if __name__ == '__main__':
    main()