# TopTalkersRanker
Gestione Di Reti 20/21 Progetto Finale Turco-Ziccolella

* Classifica dei primi X top talkers per IP o classifica dei Protocolli di livello 7 più utilizzati 

### Dipendenze Python:
* [nfstream](https://www.nfstream.org/docs/#installation-guide)
* [rrd-tool](https://oss.oetiker.ch/rrdtool/download.en.html)


### Requisiti per l'esecuzione:
* tcpdump

* [rrd-tool](https://oss.oetiker.ch/rrdtool/download.en.html)

* [grafana-rrd-server](https://github.com/doublemarket/grafana-rrd-server) -> [MIRROR](https://www.mediafire.com/file/5zbpxx3aeuqgutc/grafana-rrd-server/file)

* [Grafana](https://grafana.com/docs/grafana/latest/installation/debian/)

* [JSON API Grafana Datasource](https://grafana.com/grafana/plugins/simpod-json-datasource/)

* Python 3.x


Per eseguire il programma:

sudo python3 appy.py (necessari permessi di root per eseguire le catture)

Per arrestare il programma:

ctrl + C

## Configurazione :
  1. Inserire come DataSource grafana-rrd-server porta di default 9000![image](https://user-images.githubusercontent.com/49340033/124386911-e05c6700-dcdc-11eb-861c-aa7487f499b5.png)

  2. Opzionale: Avvio da linea di comando di grafana-rrd-server -s [stepRRD] -p [porta] -r [directory files .rrd]
  3. Creazione Api Key di Grafana ![image](https://user-images.githubusercontent.com/49340033/124387161-b6f00b00-dcdd-11eb-969a-83f36b66d624.png)

  4. sudo python3 appy.py
  5. Creazione nuova config
      1. Scelta interfaccia cattura
      2. inserimento Api Grafana [Bearer --------] 
      3. Scelta modalità di aggregazione ip/prot7
      4. Scelta RRD step sec
      5. Scelta secondi entro il quale talker deve fare traffico per non essere eliminato
      6. Scelta nel numero di cicli (RDD step sec * Numero di cicli) in cui aggiornare la classifica nella dashboard
      7. Scelta numero di talkers da esporrè nei grafici in classifica
      8. Scelta se avviare da programma grafana-rrd-server
  7. Avvio di grafana-rrd-server
  
  ## Esecuzione:
  Modalità di aggregazione
  * IP
  ![image](https://user-images.githubusercontent.com/49340033/124630156-7087e100-de82-11eb-9152-4ce0f2a689d4.png)
  * prot7
  ![image](https://user-images.githubusercontent.com/49340033/124499407-3ce38300-ddbe-11eb-92a1-602c2f9eb23b.png)

## Come Avviene la Cattura
  La cattura avviene in un thread producer che esegue il comando tcpdump con timer di RRD_Step secondi, il produttore passa al consumatore il timestamp di fine  cattura e il nome del file da aprire.I file vengono scritti ogni RRD step secondi,se una cattura non è stata consumata in questo lasso di tempo è cancellata dal produttore.
  
## Come avviene l'aggiornamento degli RRD?
  L'aggiornamento si basa sul timestamp ottenuto a fine cattura del .pcap da parte del produttore, quindi ogni rrd dei talkers + l'rrd delle statistiche verranno aggiornati sullo stesso timestamp,un punto viene considerato Unkown se non viene effettuato un update per un periodo 3*RRD_step
  
## Come Avviene la Classificazione
  I top talkers vengono classificati sulla somma del bytes in ingresso / uscita / entrambi nel periodo di aggiornamento della classifica scelto
  (Ranking Refresh Time)*RRD_Step secondi.
  I grafici dei bytes si riferiscono alla somma dei bytes del periodo di classificazione
