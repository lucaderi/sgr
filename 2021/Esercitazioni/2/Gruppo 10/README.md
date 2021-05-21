Esercizio Gestione Di Reti 2021

# Authors (gruppo 10):

# Simone Concu (s.concu@studenti.unipi.it)
# Francesco Gallicchio (f.gallicchio1@studenti.unipi.it)
# Mirko Franchi (m.franchi16@studenti.unipi.it)

Il file pkts.sh contiene lo script da eseguire.
Controllare che lo script sia eseguibile, altrimenti usare il seguente comando prima di eseguirlo
mentre vi trovate nella directory contenente lo script: chmod +x pkts.sh
Lo script determina il numero dei pacchetti effettivamente ricevuti/trasmessi su una particolare interfaccia di rete.
I grafici "Delivered Packets to the next protocol layer" e "Received Packets" potrebbero combaciare se non sono rilevati errori durante la ricezione dei pacchetti.

SYNOPSIS
	./pkts.sh interface [-s step] [-r rows]

DESCRIPTION
	Legge ogni step secondi per rows volte i valori necessari per la determinazione dei pacchetti effettivamente ricevuti/trasmessi sull'interfaccia interface.
	Fa uso del protocollo SNMP per l'ottenimento dei valori.
	I valori restituiti sono relativi all'host sul quale viene eseguito lo script.
	Di default step è uguale a 5 e rows a 60.
	Al termine dell'esecuzione viene generato un grafico che mostra l'andamento nel tempo del numero dei pacchetti ricevuti e trasmessi.

COMPATIBILITY
	In caso si faccia uso del sistema operativo Windows, decommentare la riga (a inizio dello script) che setta il font per la stampa nel grafico.

EXAMPLES
	./pkts.sh en0 -s 10 -r 60
	Legge ogni 10 secondi per 60 volte i valori.

	./pkts.sh en0
	Legge ogni 5 secondi per 60 volte i valori.

	./pkts.sh en0 -r 100
	Legge ogni 5 secondi per 100 volte i valori.
