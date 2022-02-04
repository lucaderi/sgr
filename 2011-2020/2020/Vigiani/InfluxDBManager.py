from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import ASYNCHRONOUS

#
#   Leggo i parametri dal file AgentSnmp.json
#
with open("./InfluxDB.json") as json_file:
    data = json.load(json_file)
    ip      = data['ip']
    port    = int(data['port'])
    tokens  = data['tokens']
    org     = data['org']
    bucket  = data["bucket"]
    
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
    url = str.format("http://{}:{}",ip,port)
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
