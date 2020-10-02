from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import ASYNCHRONOUS

#
# Parametri necessari per connettersi al database
#
address = "127.0.0.1"
port = 9999

#
#   Parametri per accedere al bucket presente in influxdb
#
token = "D0gTwzpTq_DemxKhPrJ3kFdMGaPnFd7Tztz7EJgX9F63ZPwzMgv142wjbP5IiEIfWDE5r9CFQCt-lBWGgNG8lA=="
org = "060b664c67469000"
bucket = "Test"

#
#   Variabile usata per accedere al database
#
write_api = None

#
#   Connessione al database
#
client = None

def create():
    global write_api,client
    url = str.format("http://{}:{}",address,port)
    client = InfluxDBClient(url=url, token=token)
    write_api = client.write_api(write_options = ASYNCHRONOUS)

def close():
    global client
    client.close()

def update(values):
    if write_api is None:
        print("Error Update")
    else:
        # Creo query insert
        data = "m1,host='desktop' "
        for key in values:
            data += str(key) + "=" + str(values[key]) + ","
        data = data[:-1:]

        # salvo i dati nel bucket
        write_api.write(bucket, org, data)
        print("Success Update:" + data)
