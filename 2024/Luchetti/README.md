# VOLUMETRIC-ATTACKS-DETECTION
Questo strumento consente di identificare attacchi attacchi volumetrici mediante l'estrazione e l'analisi dei pacchetti all'interno di file PCAP. L'analisi dei pacchetti permette di determinare se la rete è sotto attacco. È possibile specificare il protocollo dei pacchetti da analizzare tramite una variabile nel codice, in modo da identificare il tipo di attacco in corso.

Il progetto è pensato per connettersi a un firewall (in particolare Mikrotik) senza richiedere una password, grazie all'uso di chiavi SSH. Il computer si collega via SSH al dispositivo Mikrotik utilizzando una chiave pubblica per configurare, avviare e interrompere la cattura dei pacchetti, scaricare il file PCAP e rimuoverlo, pronto per essere ricreato automaticamente.

# Configuration
Prima di lanciare il programma modificare le variabili di stato per adattare il codice al proprio utilizzo.
Variabili da modificare:

```bash
  #define PACKET_THRESHOLD 1000                    //imposta la soglia di pacchetti/sec oltre il quale è considerato attacco DDOS
  #define SLEEP_INTERVAL 60                        //tempo in secondi tra una scansione e la successiva 
  #define SCP_DIR ""                               //Directory in cui il server SCP depositerà i file PCAP
  #define PACKET_TYPE IPPROTO_UDP                  //tipo di pacchetti da analizzare in base all'attacco da cui vogliamo difenderci

  #define REMOTE_FILE "./sniffer.pcap"             //Percorso del file remoto su MikroTik
  #define LOCAL_FILE "."                           //File locale
  #define MIKROTIK_USER " "                        //Nome utente MikroTik
  #define MIKROTIK_IP " "                          //Indirizzo IP del firewall MikroTik
  #define SSH_KEY_PATH "../../../../mtik_rsa"      //Percorso della chiave SSH
  #define RRD_SIZE 100                             // Numero massimo di indirizzi IP di destinazione da tracciare

```

# Listening Mode
Prima di avviare la modalità ascolto è richiesto lo scambio tra firewall mikrotik e pc delle chiavi pubbliche.

```bash
# create a new public key
ssh-keygen -t rsa -b 4096 -f ~/.ssh/mikrotik_rsa -N ""

#Condividere la chiave pubblica con miktorik
scp ~/.ssh/mikrotik_rsa.pub admin@ip:/

#aggiungere la chiave pubblica all'account:
ssh admin@ip
/user ssh-keys import public-key-file=mikrotik_rsa.pub user="MIKROTIK_USER"

#testare la connessione con:
ssh -i mikrotik_rsa MIKROTIK_USER@ip 
```

# Developing
Per compilare ed eseguire usare il comando
```bash
make
```
Per rimuovere il file oggetto creato usare il comando
```bash
make clean
```

# How to use
L'interfaccia utente si presenta nel seguente modo:

     -----------------------------------------------------------------------------------------------------------------------------------------------
    |      __      __   _                      _        _              _   _             _              _      _            _   _                   |
    |      \ \    / /  | |                    | |      (_)            | | | |           | |            | |    | |          | | (_)                  |
    |       \ \  / /__ | |_   _ _ __ ___   ___| |_ _ __ _  ___    __ _| |_| |_ __ _  ___| | _____    __| | ___| |_ ___  ___| |_ _  ___  _ __        |
    |        \ \/ / _ \| | | | | '_ ` _ \ / _ \ __| '__| |/ __|  / _` | __| __/ _` |/ __| |/ / __|  / _` |/ _ \ __/ _ \/ __| __| |/ _ \| '_ \       |
    |         \  / (_) | | |_| | | | | | |  __/ |_| |  | | (__  | (_| | |_| || (_| | (__|   <\__ \ | (_| |  __/ ||  __/ (__| |_| | (_) | | | |      |
    |          \/ \___/|_|\__,_|_| |_| |_|\___|\__|_|  |_|\___|  \__,_|\__|\__\__,_|\___|_|\_\___/  \__,_|\___|\__\___|\___|\__|_|\___/|_| |_|      |
    |                             premi:                                                                                                            |
    |                             1: se hai già un file di tipo PCAP pronto da analizzare;                                                          |
    |                             2: se vuoi entrare in modalità 'analisi dei limiti'                                                               |
    |                             3: se vuoi entrare in modalità ascolto                                                                            |
     -----------------------------------------------------------------------------------------------------------------------------------------------

premre i tasti: 1 se è presente all'interno della cartella un file .pcap da analizzare,
                2 se si vuole lanciare la modalità analisi dei limiti
                3 se si vuole mettere il programma in modalità ascolto, il quale preleva in maniera automatica il file pcap 

se la scelta è stata 1:

    Elenco dei file disponibili con estensione .pcap:
            1: ...
            2: ...
            3:  ...
    Inserisci il numero corrispondente al file da analizzare: 1
    
      Analyzing file: ...
    
    Final interval duration:  seconds
    No DDOS attack detected!  packets/sec or bytes/sec
    
    Total capture time:  seconds
    Total Packets: , Total Bytes:
    Overall Packets/sec: , Overall Bytes/sec: KB/sec
    
                                    Vuoi analizzare un nuovo file?
                                    y:yes oppure n:no y

se si vuole analizzare un nuovo file premere y altrimenti premere n.

se la scelta è stata 2: effettuerà una scansione per "max_iterations" al fine di ottenere un limite superiore della rete e in autonomia lancia una scansione classica della rete proseguendo con la scelta 3.
La scansione sarà effettuata per 2 cicli di SLEEP_INTERVAL (tempo tra una scansione e la successiva): se SLEEP_INTERVAL è di 120 secondi, la scansione sarà effettuata per 240 secondi.

se la scelta è stata 3:
      in automatico eseguirà le procedure di:
        
                  -> start
                  -> stop
                  -> download
                  -> remove

                      
        



