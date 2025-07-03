import csv
from collections import Counter
from datetime import datetime

def modbus_timeline(csv_file):
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

if __name__ == '__main__':
    modbus_timeline("parsed_data.csv")
