import json
import sys
from collections import defaultdict
from time import sleep,time
from easysnmp import Session

#
#   Carico i moduli ProcessData e DataBase
#   Se non specificati allora il comportamento di default è:
#   ProcessData ->  return data
#   DataBase    ->  salva i dati in formato json
#
try:
    ProcessData = __import__(sys.argv[1])
    DataBase = __import__(sys.argv[2])
except:
    ProcessData = __import__("ProcessData")
    DataBase = __import__("Database")

#
# Controllo che i moduli hanno implementato i metodi necessari
#
if hasattr(ProcessData,'process') is False:
    print("Module:" + sys.argv[1] + " not have process function")
    exit(-1)

if hasattr(DataBase, "create") is False:
    print("Module:" + sys.argv[2] + " not have update function")
    exit(-1)

if hasattr(DataBase,"update") is False:
    print("Module:" + sys.argv[2] + " not have create function")
    exit(-1)

if hasattr(DataBase,"close") is False:
    print("Module:" + sys.argv[2] + " not have close function")
    exit(-1)

#
#   Leggo i parametri dal file AgentSnmp.json
#
with open("./AgentSnmpConf.json") as json_file:
    data = json.load(json_file)
    version = data['version']
    community = data['community']
    address = data['address']
    port = data['port']
    oids = data["OIDS"]
    interval = float(data['interval'])

#
# Instauro Connessione con l'agent snmp
#
session = Session(hostname=address, community=community, version=int(version))

#
# Creo il database
#
DataBase.create()

#
# Ad intervalli regolari interrogo l'agent snmp per ottenere i dati
# Poi li processo e successivamente li salvo
#
currentTime = time()
try:
    while True:
        sleepTime = time() - currentTime

        if sleepTime < interval:
            sleepTime = interval - sleepTime
            sleep(sleepTime)

        currentTime = time()

        values = {}
        values = defaultdict(lambda: "", values)

        for id in oids:
            el = session.get(id)
            values[el.oid] += "%" + el.value

        values = ProcessData.process(values)

        DataBase.update(values)
except:
    DataBase.close()