import json
from collections import defaultdict
from time import sleep,time
from easysnmp import Session
import Database
import ProcessData

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
Database.create()

currentTime = time()
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

    Database.update(values)
