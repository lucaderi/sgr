import csv
from collections import defaultdict

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

if __name__ == '__main__':
    classify_roles("parsed_data.csv")
