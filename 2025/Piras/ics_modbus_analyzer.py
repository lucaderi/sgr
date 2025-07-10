import json, csv
import pyshark
import os, subprocess
from datetime import datetime
from multiprocessing import Pool
from collections import Counter
from collections import defaultdict

def split_pcap(input_pcap, output_prefix="chunk", packets_per_file=500):
    print("[*] Splitting pcap file...")
    cmd = ["editcap", "-c", str(packets_per_file), input_pcap, f"{output_prefix}.pcap"]
    subprocess.run(cmd, check=True)


def parse_chunk(pcap_file):
    #print(f"[+] Parsing {pcap_file}...")
    cap = pyshark.FileCapture(pcap_file, display_filter='modbus', keep_packets=False)
    rows = []
    for pkt in cap:
        try:
            rows.append([str(pkt.sniff_time), pkt.ip.get('src', 'N/A'), pkt.ip.get('dst', 'N/A'), pkt.modbus.get('func_code', 'N/A')])
            
        except AttributeError:
            continue
    cap.close()
    return rows


def collect_chunks(prefix="chunk"):
    return sorted([f for f in os.listdir('.') if f.startswith(prefix) and f.endswith(".pcap")])


def clean_chunks(prefix="chunk"):
    for f in collect_chunks(prefix):
        os.remove(f)
    print("[*] Temporary chunk files removed.")
    
def analyze(csv_file, output_json, expected, blacklist):
    anomalies, func_counts, src_ips = [], Counter(), Counter()

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            func = row['FunctionCode']
            func_counts[func] += 1
            src_ips[row['SrcIP']] += 1

            if func not in expected:
                anomalies.append({
                    'time': row['Time'],
                    'src': row['SrcIP'],
                    'dst': row['DstIP'],
                    'func': func,
                    'reason': 'Unexpected function code'
                })
            
            elif func in blacklist:
                anomalies.append({
                    'time': row['Time'],
                    'src': row['SrcIP'],
                    'dst': row['DstIP'],
                    'func': func,
                    'reason': 'Blacklisted function code'
                })

    with open(output_json, 'w') as f:
        json.dump(anomalies, f, indent=2)

    print(f"[+] {len(anomalies)} anomalie salvate in {output_json}\n")
    print("[+] Top Function Code:")
    for func, count in func_counts.most_common(5):
        print(f"  FC {func} -> {count} packets")

    print("\n[+] Top Client IPs:")
    for ip, count in src_ips.most_common(3):
        print(f"  {ip} -> {count} packets")
        
    hourly = Counter()
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = datetime.strptime(row['Time'], "%Y-%m-%d %H:%M:%S.%f")
            key = t.strftime("%H:%M")
            hourly[key] += 1

    print("\n[+] Time distribution:")
    for t, c in sorted(hourly.items()):
        bar = '#' * (c // 100)
        print(f"{t} | {bar} ({c})")
            
def classify_roles(csv_file):
    roles = defaultdict(lambda: 'unknown')
    usage = defaultdict(set)

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            usage[row['SrcIP']].add(row['FunctionCode'])

    for ip, funcs in usage.items():
        if '6' in funcs or '5' in funcs or '15' in funcs or '16' in funcs:
                    roles[ip] = 'PLC'
        elif '3' in funcs or '4' in funcs:
                    roles[ip] = 'HMI'
    
    print("\n[+] IP Classification:")
    for ip, role in roles.items():
        print(f"  {ip} => {role}")
        
def build_profiles(csv_file, profile_json):
    profiles = defaultdict(lambda: {'function_codes': set(), 'count': 0})

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['SrcIP']
            profiles[ip]['function_codes'].add(row['FunctionCode'])
            profiles[ip]['count'] += 1

    # Convert set to list for JSON serialization
    for ip in profiles:
        profiles[ip]['function_codes'] = list(profiles[ip]['function_codes'])

    with open(profile_json, 'w') as out:
        json.dump(profiles, out, indent=2)
    print(f"[+] Profiles written to {profile_json}")
    
def load_config(path="config.cfg"):
    config = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            # gestisci liste e numeri
            if "," in value:
                value = value.split(",")
            elif value.isdigit():
                value = int(value)
            config[key] = value
    return config


def main():
    config = load_config("config.cfg")
    
    input_pcap = config.get("input_pcap", "modbus_sample.pcap)
    output_csv = config.get("parsed_csv","parsed_data.csv")
    threads = config.get("threads", 16)
    expected = config.get("expected_function_codes", "1,2,3,4,5,6,15,16")
    blacklist = config.get("blacklist_function_codes", "")
    anomalies_json = config.get("anomalies_json", "anomalies.json")
    profiles_json = config.get("profile_json", "profiles.json")
    
    split_pcap(input_pcap)

    chunks = collect_chunks()
    all_rows = []

    with Pool(threads) as pool:
        results = pool.map(parse_chunk, chunks)
        for r in results:
            all_rows.extend(r)

    with open(output_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Time', 'SrcIP', 'DstIP', 'FunctionCode'])
        writer.writerows(all_rows)

    clean_chunks()
    print("[✓] Parsing completato e file CSV generato.")
    
    analyze(output_csv, anomalies_json, expected, blacklist)
    classify_roles(output_csv)
    build_profiles(output_csv, profiles_json)


if __name__ == '__main__':
    main()
