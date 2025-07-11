import json, csv
import pyshark
from datetime import datetime
from collections import Counter
from collections import defaultdict
    
def analyze(pcap_file, csv_file, output_json, expected, blacklist):
    anomalies, func_counts, src_ips = [], Counter(), Counter()
    
    print(f"[+] Parsing {pcap_file}...")
    
    cap = pyshark.FileCapture(pcap_file, display_filter='modbus', keep_packets=False)
    rows = []
    
    for pkt in cap:
        
        try:
            rows.append([
                 str(pkt.sniff_time), 
                 pkt.ip.get('src', 'N/A'), 
                 pkt.ip.get('dst', 'N/A'), 
                 pkt.modbus.get('func_code', 'N/A'),
                 pkt.tcp.stream or 'N/A'
                 ])
            
        except AttributeError:
            
            continue
        
    with open(csv_file, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Time', 'SrcIP', 'DstIP', 'FunctionCode', 'TCPStream'])
        writer.writerows(rows)
        
    cap.close()
    
    print("[✓] Parsing completato e file CSV generato.")

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
    usage = defaultdict(lambda: {'as_dst_fc': set(), 'as_src_fc': set()})
    all_ips = set()
    roles = {}
    seen_streams = set()

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                fc = int(row['FunctionCode'])
                stream = int(row['TCPStream'])
            except ValueError:
                continue

            src = row['SrcIP']
            dst = row['DstIP']
            all_ips.update([src, dst])

            # Solo la prima richiesta per ogni stream
            if stream in seen_streams:
                continue
            seen_streams.add(stream)

            if fc in {3, 4}:
                usage[src]['as_src_fc'].add(fc)
            if fc in {5, 6, 15, 16}:
                usage[dst]['as_dst_fc'].add(fc)

    # Classificazione di tutti gli IP visti
    for ip in all_ips:
        dst_fc = usage[ip]['as_dst_fc']
        src_fc = usage[ip]['as_src_fc']
        if dst_fc:
            roles[ip] = 'PLC'
        elif src_fc:
            roles[ip] = 'HMI/SCADA'
        else:
            roles[ip] = 'Unknown'

    print("\n[+] Classificazione completa IP (prima richiesta per stream):")
    for ip in sorted(roles.keys()):
        print(f"  {ip:<15} => {roles[ip]}")
        
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
    
    input_pcap = config.get("input_pcap", "modbus_sample.pcap")
    output_csv = config.get("parsed_csv","parsed_data.csv")
    expected = config.get("expected_function_codes", "1,2,3,4,5,6,15,16")
    blacklist = config.get("blacklist_function_codes", "")
    anomalies_json = config.get("anomalies_json", "anomalies.json")
    profiles_json = config.get("profile_json", "profiles.json")
    
    analyze(input_pcap, output_csv, anomalies_json, expected, blacklist)
    classify_roles(output_csv)
    build_profiles(output_csv, profiles_json)


if __name__ == '__main__':
    main()
