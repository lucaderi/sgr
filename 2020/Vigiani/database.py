from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


#   Param InfluxDB
token = "yIpbQWbD07uwmgIyuy8rSDnDuvZ2wb04Xj7z6fVRMUrvxjnLCS9VaYBO_q5gbVRLiKJMIhys3YEdvfoBqujkkw=="
org = "GestioneReti"
bucket = "GestioneReti"

#   Connection To InfluxDB
client = InfluxDBClient(url="http://127.0.0.1:9999",token=token)


# Use InfluxDB Line Protocol to write data
def update(data):

    write_api = client.write_api(write_options=SYNCHRONOUS)
    for key in data.keys():
        dat = 'ex2,country="{}",latitude={},longitude={}  consume={}'.format(data[key][0],data[key][1],data[key][2],data[key][3])
        write_api.write(bucket, org, dat)

