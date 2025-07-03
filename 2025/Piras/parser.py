import pyshark
import csv
import os
import subprocess
from multiprocessing import Pool

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


def main():
    input_pcap = "modbus_sample.pcap"
    output_csv = "parsed_data.csv"
    split_pcap(input_pcap)

    chunks = collect_chunks()
    all_rows = []

    with Pool(16) as pool:
        results = pool.map(parse_chunk, chunks)
        for r in results:
            all_rows.extend(r)

    with open(output_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Time', 'SrcIP', 'DstIP', 'FunctionCode'])
        writer.writerows(all_rows)

    clean_chunks()
    print("[✓] Parsing completato e file CSV generato.")


if __name__ == '__main__':
    main()