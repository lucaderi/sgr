from time import sleep
import threading
import Productor    #analizza i pacchetti in entrata
import Consumer     #elabora i pacchetti
import database     #aggiornamento del database


#   INIZIO CATTURA PACCHETTI
Productor.capture()


#   INIZIO ELABORAZIONE PACCHETTI
consumator = threading.Thread(target=Consumer.elaborate)
consumator.start()


#   AGGIORNO DATABASE TEMPORALE
sleep(60)
data = Consumer.exportData()
database.update(data)


print(("finito :)"))


