from datetime import datetime
import time
import json
import os


with open('Cowrie_logs_test.json', 'r') as file:
  lines = file.readlines()
  oldTsIso = 0
  STARTED = False
  with open('syncedLog.json', 'a') as dst:
    for line in lines:
      data = json.loads(line)
      newTs = data['timestamp']
      newTsIso = datetime.fromisoformat(newTs[:-1])
      newTsIso = newTsIso.timestamp() * 1e9
      newTsNsec = int(newTsIso)
      if STARTED:
        delta = newTsNsec - oldTsIso
      else:
        delta = 0
        STARTED = True
      print("delta: " + str(delta))
      time.sleep(delta / 1e9)
      dst.write(line)
      dst.flush()
      oldTsIso = newTsNsec
