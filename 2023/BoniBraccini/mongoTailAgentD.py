import json
import time
import geoip2.database
from pymongo import MongoClient
import pytz
from dateutil import parser
from timezonefinder import TimezoneFinder

DIONAEA_LOGS_PATH="<YOUR DIONAEA LOGS PATH>"
MONGO_ISTANCE = "<YOUR_ONGO_IP:PORT>"
LAST_LINE_FILE = "<FILE WHERE TO SAVE LAST READ LINE" # (Has to be created manually)
CITY_DATABASE_FILE  = "<MAX_MIND_CITY_DB_PATH/geoLite2-City.mmdb>"
DB_NAME = "<YOUR_MONGODB_DB_NAME>"
MONGO_COLL = "<YOUR_MONGODB_COLLETION_NAME>"



client = MongoClient(MONGO_ISTANCE)
db = client[DB_NAME]
collection = db[MONGO_COLL]

schema = {
    "connection_type": str,
    "local_host": str,
    "connection_protocol": str,
    "local_port": int,
    "connection_root": int,
    "timestamp": str,
    "remote_port": int,
    "download_url" : str,
    "download_md5_hash" : str,
    "connection": int,
    "connection_parent": int,
    "remote_hostname": str,
    "connection_transport": str,
    "login_password": str,
    "login_username": str,
    "login": str,
    "remote_host": str,
    "eventid": str
}


def get_timezone_from_coordinates(latitude, longitude):
    tf = TimezoneFinder()
    timezone = pytz.timezone(tf.timezone_at(lng=longitude, lat=latitude))
    return timezone


def convert_timestamp_to_timezone(timestamp, latitude, longitude):
    try:
        utc_time = parser.parse(timestamp)
    except ValueError:
        print("Invalid timestamp format.")
        return None

    timezone = get_timezone_from_coordinates(latitude, longitude)
    if timezone is None:
        print("Invalid latitude/longitude or timezone not found for the coordinates.")
        return None

    try:
        localized_time = utc_time.astimezone(timezone)
    except ValueError:
        print("Invalid timestamp provided.")
        return None

    return localized_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def read_and_insert_lines():
    print("Reading and inserting lines... (DION VERSION)")
    last_line = get_last_line()
    new_lines = []
    with open('/media/root/HON1/ctrl1/syncedLogDion.json', 'r') as file:
        lines = file.readlines()
        if not last_line or last_line+'\n' not in lines:
            new_lines = lines
        else:
            last_line_index = lines.index(last_line+'\n')
            new_lines = lines[last_line_index+1:]
    for line in new_lines:
        data = json.loads(line)
        ip = data['remote_host']
        if not ip:
         continue
        coords = get_ip_coords(ip)
        data['latitude'] = coords['latitude']
        data['longitude'] = coords['longitude']
        data['country'] = coords['country']
        data['attacker_timestamp'] = convert_timestamp_to_timezone( data['timestamp'], float(data['latitude']), float(data['longitude']))
        if(data['eventid'] == "download"):
            data['virustotal'] = 'https://www.virustotal.com/gui/file/' +  data['download_md5_hash']
        collection.insert_one(data)
    if new_lines:
        update_last_line(new_lines[-1])
        print(f"Inserted {len(new_lines)} new lines.")
    else:
        print("No new lines to insert.")

def get_last_line():
    try:
        with open(LAST_LINE_FILE, 'r') as file:
            last_line = file.read().strip()
    except FileNotFoundError:
        last_line = ''
    return last_line


def get_ip_coords(ip):
  with geoip2.database.Reader(CITY_DATABASE_FILE) as reader:
    try:
     response = reader.city(ip)
     return { 'longitude': response.location.longitude, 'latitude': response.location.latitude, 'country': response.country.iso_code}
    except geoip2.errors.AddressNotFoundError:
     return { 'longitude': 0, 'latitude': 0, 'country':  None}
     



def update_last_line(last_line):
    with open(LAST_LINE_FILE, 'w') as file:
        file.write(last_line)

while True:
    read_and_insert_lines()
    time.sleep(60)
