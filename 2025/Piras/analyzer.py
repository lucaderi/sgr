import csv, json
from collections import Counter

EXPECTED = {'1','2','3','4','5','6','15','16'}

def analyze(csv_file, output_json):
    anomalies, func_counts, src_ips = [], Counter(), Counter()

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            func = row['FunctionCode']
            func_counts[func] += 1
            src_ips[row['SrcIP']] += 1

            if func not in EXPECTED:
                anomalies.append({
                    'time': row['Time'],
                    'src': row['SrcIP'],
                    'dst': row['DstIP'],
                    'func': func,
                    'reason': 'Unexpected function code'
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

if __name__ == '__main__':
    analyze("parsed_data.csv", "anomalies.json")
