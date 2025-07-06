import csv
import json
from collections import defaultdict

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

if __name__ == '__main__':
    build_profiles("parsed_data.csv", "profiles.json")
