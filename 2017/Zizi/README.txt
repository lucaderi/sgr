-Compilare eseguendo Make sfd

-Eseguire l'eseguibile sfd con le opzioni 
	-i seleziona l'interfaccia di ingresso,default lo
	-g indicare il nome del file del grafico generato da RRDtool, default grafico.png
	-n indicare il nome dell'archivio RRA, default myrrd.rrd
	-t indivare il valore della soglia.
Il programma è scritto per catturare pacchetti IPV4 su ETHERNET

Si possono eseguire dei test con il tool hping3 tramite i comandi.

(Per simulare un SYNFLOOD)
hping3 -i u1000 -p <destport> -S -c <Numero pacchetti> -V IPDest
(Per simulare un Port Scanning) 
hping3 -i u1000 -S -p <porta>++ -c <Numero pacchetti> -V IPDest




