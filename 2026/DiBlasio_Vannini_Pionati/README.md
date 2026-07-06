Raccogliere metriche di rete da uno o più agenti SNMP e gestire anche notifiche asincrone tramite trap.

Il programma avrebbe il ruolo di SNMP Manager e interrogherebbe periodicamente uno o più agenti, ad esempio un servizio snmpd eseguito in ambiente Linux o Docker. Le informazioni raccolte farebbero riferimento principalmente alla MIB-II, in modo da utilizzare metriche standard e facilmente disponibili.

Componenti principali del progetto:

SNMP Poller
esegue interrogazioni periodiche verso gli agenti SNMP;
utilizza SNMPv2c come versione iniziale del protocollo;
legge informazioni generali del dispositivo, come sysUpTime e dati del gruppo system;
raccoglie statistiche delle interfacce tramite ifTable.
Raccolta delle metriche
byte in ingresso e in uscita sulle interfacce;
stato operativo delle interfacce;
eventuali errori o scarti sui pacchetti;
informazioni base utili a capire lo stato del dispositivo monitorato.
Calcolo di metriche derivate
traffico stimato in Mbps;
variazione dei contatori tra due letture successive;
incremento degli errori tra due polling consecutivi;
individuazione di possibili cambiamenti anomali nello stato delle interfacce.
SNMP Trap Receiver
componente in ascolto per ricevere trap SNMP;
gestione di trap standard come linkDown, linkUp, coldStart, warmStart e authenticationFailure;
registrazione degli eventi ricevuti;
possibile attivazione di un polling immediato dopo la ricezione di una trap rilevante.
Salvataggio e output dei dati
salvataggio delle misure raccolte in formato semplice, ad esempio CSV;
registrazione separata degli eventi ricevuti tramite trap;
produzione di un output finale utile per analizzare traffico, stato delle interfacce ed eventi rilevati.