# Forecasting the server status using single/double exponential smoothing
## Introduzione
Il progetto ha come obiettivo la creazione di uno script in python in grado di prevedere lo stato di un server attraverso l'utlizzo di single & double exponential smoothing e l'analisi di risposte http: tramite prometheus si invia la query ***probe_http_duration_seconds*** al server, catturando la risposta di quest'ultimo è possibile analizzare la duranta della richiesta http per ogni sua fase (connect, processing, resolve, tls, transfer). **IMPORTANTE: per l'utilizzo della query *probe_http_duration_seconds* è necessaria la configurazione e l'utilizzo di una [Blackbox](https://github.com/prometheus/blackbox_exporter)**
## Prerequisiti e Esecuzione
Per poter utilizzare il programma è necessario eseguire i comandi

`pip3 install requests` 

`pip3 install matplotlib`

Per poi eseguire il programma con il comando

`python3 main.py`

L'applicazione permette di fare analisi su dati prelevati direttamente da Prometheus o da file JSON. Per la cattura dei dati con Prometheus è necessario utilizzare in aggiunta a quest'ultimo una BlackBox. Entrambi sono scaricabili direttamente dal [sito ufficiale di Prometheus](https://prometheus.io/download/).
Dopo aver scaricato la versione adeguata al proprio sistema, devono essere copiati i file di configurazione *.yaml* contenuti nella cartella *prometheus* della repository direttamente nelle cartelle *blackbox* e *prometheus* scaricate. A questo punto possiamo lanciare la blackbox e successivamente prometheus, quest'ultimo permetterà di effettuare query diverse al seguente link: http://localhost:9090/
## Descrizione
* **main.py:** è il main file da mandare in esecuzione
* **guy.py:** contiene alcune funzioni per la creazione e la gestione della GUI
* **smoothing.py:** contiene gli algoritmi di forecasting (single & double exponential smoothing) e una funzione utile per il calcolo dell'SSE
* **utilities.py:** contiene alcune funzioni utili per la letture dei dati da un file .json o direttamente da prometheus
## Esempio di esecuzione
Pagina Iniziale:

![](image_gui/start_page.png)

Single Exponential Smoothing:

![](image_gui/single_smoothing.png)

Double Exponential Smoothing:

![](image_gui/double_smoothing.png)

