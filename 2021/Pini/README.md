# WiNetScanner
## Introduzione

Il programma ha lo scopo di rilevare i dispositivi (client), e gli access points disponibili , attraverso il monitoraggio delle informazioni (pacchetti) in transito nella rete.

Tra tutti i pacchetti sniffati sulla rete due sono quelli interessanti per raggiungere gli scopi preposti: *Probe request* e *Beacon*. 

- I **probe request frames** vengono utilizzati dai dispositivi (client) come delle sonde, per individuare reti wireless presenti nel suo raggio d’azione, e richiedere informazioni sulla connessione, necessarie per iniziare la sequenza di autenticazione.
Da notare che, a meno che non venga specificato un SSID (nome delle rete wi-fi), ogni access point che riceverà la richiesta risponderà.

- I **beacon frames** vengono trasmessi continuamente dagli access points per annunciarsi, ed aiutando così i client a trovare quali di essi (gli AP) sono disponibili nel proprio raggio di rete.

## Prerequisiti

Per il funzionamento del software è necessario aver installato:
- ```python3```
- ```scapy```: per acquisire e decodificare i pacchetti nella rete
- ```aircrack-ng```: per abilitare il monitor mode

In programma è stato sviluppato e testato in ambiente Linux.

## Descrizione

Il programma è composto di 3 moduli:

- ```WiNetScanner.py```: modulo principale, contenente il main, e le funzioni di sniffing e filtraggio

- ```Client.py```: contenente la definizione della classe Client con i relativi metodi

- ```AP.py```: contenente la definizione della classe AccessPoint con i  relativi metodi

## Esecuzione

### Usage
Attraverso l'opzione ```-h``` è possibile visualizzare un breve helper delle opzioni possibili.

 ```sudo python3 WiNetScanner.py -h```
 
```-h, --help``` show this help message and exit
```-m MODE, --mode MODE a=access points, c=clients, b=both```
```-i INTERFACE, --interface INTERFACE``` specify interface to listen on
```-t TIME, --time TIME``` specify time (in sec) listening for packets (type 'u' for unlimited) (press 'Ctrl+C' to stop)
```-verbose```


### Esempio di esecuzione
```sudo python3 WiNetScanner.py -m b -t 60 -v``` 
Fa la scansione sia degli access points, che dei clients, intercettando paccheti per 60 secondi, con l'opzione verbose (mostra anche i pacchetti catturati).
Non avendo specificato l'interfaccia, utilizzerà quella di default.

    Using default interface: wlp3s0
    `airmon-ng  start wlp3s0` ran with exit code 0
    Gathering information...

    ---------------[ Beacon Packet Captured ]-----------------------
    Access Point MAC : 14:14:59:ac:59:71  
    Access Point Name [SSID]  : b'Vodafone-A45452810'
    Access Point Received Signal Strength [RSSI] : -74 dBm
    Access Point Crypto : {'WEP'}


    ---------------[ Beacon Packet Captured ]-----------------------
    Access Point MAC : 6a:14:59:ac:59:72  
    Access Point Name [SSID]  : b'Vodafone-WiFi'
    Access Point Received Signal Strength [RSSI] : -74 dBm
    Access Point Crypto : {'OPN'}

    ----NEW CLIENT---

    ---------------[ Probe Packet Captured ]-----------------------
    Client MAC           : 86:13:f7:19:4c:79   
    Access Point Name [SSID] : b''


    ---------------[ Beacon Packet Captured ]-----------------------
    Access Point MAC : d4:35:1d:5d:2c:b8  
    Access Point Name [SSID]  : b'TIM-24210104'
    Access Point Received Signal Strength [RSSI] : -89 dBm
    Access Point Crypto : {'WPA2/PSK'}

    ----NOT NEW CLIENT, BUT WITH UNSEEN ACCESS POINT [SSID]

    ---------------[ Probe Packet Captured ]-----------------------
    Client MAC           : 86:13:f7:19:4c:79   
    Access Point Name [SSID] : b'Vodafone-A45452810'


    ---------------[ Beacon Packet Captured ]-----------------------
    Access Point MAC : fc:15:b4:65:d1:63  
    Access Point Name [SSID]  : b'HP-Print-63-Officejet 4630'
    Access Point Received Signal Strength [RSSI] : -91 dBm
    Access Point Crypto : {'WPA2/PSK'}

    ----NEW CLIENT---

    ---------------[ Probe Packet Captured ]-----------------------
    Client MAC           : 94:3a:91:2c:7f:3f   
    Access Point Name [SSID] : b''

    ----NEW CLIENT---

    ---------------[ Probe Packet Captured ]-----------------------
    Client MAC           : 3a:2e:db:92:a5:16   
    Access Point Name [SSID] : b''

    ----NEW CLIENT---

    ---------------[ Probe Packet Captured ]-----------------------
    Client MAC           : b8:e8:56:24:62:ea   
    Access Point Name [SSID] : b'Vodafone-A45452810'

    `airmon-ng  stop wlp3s0mon` ran with exit code 0

    ====================================== ACCESS POINTS ======================================
    Number of seen AP:  4

    AP MAC [BSSID]       AP NETWORK NAME [SSID]           [RSSI]                Crypto
    14:14:59:ac:59:71    b'Vodafone-A45452810'            -74 dBm -> Low        {'WEP'}
    6a:14:59:ac:59:72    b'Vodafone-WiFi'                 -74 dBm -> Low        {'OPN'}
    d4:35:1d:5d:2c:b8    b'TIM-24210104'                  -89 dBm -> Low        {'WPA2/PSK'}
    fc:15:b4:65:d1:63    b'HP-Print-63-Officejet 4630'    -91 dBm -> Low        {'WPA2/PSK'}


    =================== CLIENTS ===================
    Number of seen clients:  4

    CLIENT MAC           AP NETWORK NAME [SSID]
    86:13:f7:19:4c:79    b'Vodafone-A45452810'
    94:3a:91:2c:7f:3f
    3a:2e:db:92:a5:16
    b8:e8:56:24:62:ea    b'Vodafone-A45452810'

\
Dalla scansione risultano 
- 4 access points
- 4 clients di cui due hanno specificato anche un SSID

