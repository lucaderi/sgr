README file.

--------------------------
INSTALLAZIONE
Da installare sulla tua macchina Linux prima di usare gli script:
   1) python
     1.1) pyping package
     1.2) python-rrdtool package
   2) RRDtool

--------------------------
SETUP

1)
Si deve modificare il file "mailfunction.py" inserendo i propri dati, per l'invio della mail.
Per aiutarti a controllare che tutto funzioni, ho creato il file "tryMail.py". Mandandolo in esecuzione usa il file "mailfunction.py" per spedire una mail di prova.
Così puoi fare qualche prova (devi impostare correttamente il tuo server SMTP, l'indirizzo e la password di chi invia la mail, l'indirizzo di chi la riceve) senza mandare in esecuzione lo script principale.

2)
Si deve modificare il file "hostname.conf" inserendo, uno per riga, i nomi degli host di cui si vuole controllare la raggiungibilità. 
Sono ammessi sia i nomi (es. google.it) che gli indirizzi IP (es. 172.3.6.219)

--------------------------
ESECUZIONE

---Polling e alert
A questo punto si può mettere in esecuzione "PingChecker.py".
Si deve mettere in esecuzione con i diritti di amministratore.
Si deve specificare con l’opzione -s quanti secondi far passare tra i cicli di polling.
(es. sudo python PingChecker.py -s 35)
("sudo python PingChecker.py -h" mostra l'input che si aspetta lo script)

PingChecker creerà un file .rrd per salvare i dati di polling per ogni host.
Come detto, se non un host non risulta raggiungibile per 2 cicli di polling, viene mandata una mail
di alert.

---Rappresentazione
Se siamo interessati alla visualizzazione dei dati, possiamo mandare in esecuzione
"doGraph.py".
Nel mandare in esecuzione questo script bisogna specificare lo stesso intero che abbiamo passato a
"PingChecker.py".
(es. python doGraph 35)
Questo script creerà ciclicamente dei grafici dagli .rrd, e una pagina "graphViewer.html" in cui si possono
visualizzare.   

