******************** WHOML = what's happening on my lan ********************

* Author: Federico Cappelli <cappellf@cli.di.unipi.it> <federico@federicocappelli.net>
* Version: alpha 1
* date: 2/05/2010

* Description:
Lo scopo del progetto Whoml è quello di fornire ai non addetti ai lavori uno strumento facile e intuitivo per comprendere cosa sta succedendo all'interno di una rete Lan, mostrando una serie di informazioni (da ampliare con le versioni successive) su gli host collegati e sulla loro attività.
Info host: nome, ip, mac, data ultima volta visto attivo, siti web visitati, user agent, ultimi protocolli di livello di rete utilizzati, ultimi protocolli di livello applicazione utilizzati.
L'interfaccia temporanea mostra, ad intervalli di 5 secondi, gli host conosciuti con relative informazioni e i flussi di dati scambiati tra host:
----------- FreeVac-----------
Host : 10.0.0.7
Mac: 0:23:6c:f4:41:b3
Last seen Alive: Last seen Alive: Mon Mar 15 15:31:44 2010
Websites: 
  www.repubblica.it
  adagiojs.repubblica.it
  scripts.kataweb.it
  adagiof3.repubblica.it

Transport Protocol: ICMP (1), TCP (6), UDP (17), 

User Agent:  Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; it; rv:1.9.2) Gecko/20100115 Firefox/3.6

Application Protocol: http (80) ( TCP ) , domain (53) ( UDP ) , netbios-ns (137) ( UDP ) , https (443) ( TCP ) , ntp (123) ( UDP ) , 
------------------------------

L'interfaccia temporanea web-based si trova su http://127.0.0.1:8080
Altro obbiettivo del progetto è quello di essere multi platform e versatile, obbiettivo perseguito con l'uso della libreria boot e dell'interfaccia web-based.

per ulteriori informazioni visitare http://www.federicocappelli.net/whoml/

* Third part library:
- Libpcap 1.0.0
- Boost 1.40.0

* Unix Tool:
- netstat 
- fping 2.4b2
- arp 
- nslookup 
- nmblookup 3.0.28a-apple

* Compile:

make

* Use:
whoml -i <interface> [-w] [-v]
         -i <interface> | Interfaccia di ascolto
         -w abilita il webserver (disabilitata fino alla creazione della gui)
         -v Modalita' verbosa
Esempio: whoml -i eth0 -w -v

to stop: ctrl + c and wait the termination or click on "Termina" in the web interface