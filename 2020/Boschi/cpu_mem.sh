#!/usr/bin/env bash
#MIB da cui prendo le informazioni: UDC-SNMP-MIB DEFINITIONS



#FUNZIONE CHE PREDNE LE INFO SUL CARICO DELLA CPU-----------------------------------------------------
function getCpuInfo {
	#carico CPU ultimo minuto
	CPU_LOAD_1m=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.10.1.3.1)
	CPU_LOAD_1m=${CPU_LOAD_1m##*:}

	#carico CPU ultimi 5 minuti
	CPU_LOAD_5m=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.10.1.3.2)
	CPU_LOAD_5m=${CPU_LOAD_5m##*:}

	#carico CPU ultimi 10 minuti
	CPU_LOAD_10m=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.10.1.3.3)
	CPU_LOAD_10m=${CPU_LOAD_10m##*:}
}
#-----------------------------------------------------------------------------------------------------



#FUNZIONE CHE PRENDE LE VARIE INFORMAZIONI SULLA MEMORIA-------------------------------------------------------
function getMemInfo {
	#prendo la memoria disponibile, usando l'OBJECT-TYPE memAvailReal del MIB
	MEMORY_AVAIABLE=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.4.memAvailReal.0)

	#prendo la memoria totale, usando l'OBJECT-TYPE memTotalReal del MIB
	MEMORY_TOTAL=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.4.memTotalReal.0)

	#prendo la memoria usata per buffer, usando l'OBJECT_TYPE memBuffer
	MEMORY_BUFFER=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.4.memBuffer.0)

	#prendo la memoria usata per la cache, usando l'OBJECT_TYPE memCached
	MEMORY_CACHED=$(snmpget -v 1 -c $COMMUNITY $HOST .1.3.6.1.4.1.2021.4.memCached.0)



	#---------------Costruzione delle stringhe rimuovendo le parti inutili----------



	#memoria buffer (bufF)
	MEMORY_BUFFER=${MEMORY_BUFFER##*:}    #conservo la parte dopo gli ultimi duepunti

	#memoria cached (cached)
	MEMORY_CACHED=${MEMORY_CACHED##*:}     #conservo la parte dopo gli ultimi duepunti

	#memoria disponibile (free)
	MEMORY_AVAIABLE=${MEMORY_AVAIABLE##*:} #conservo la parte dopo gli ultimi duepunti

	#memoria totale (tot)
	MEMORY_TOTAL=${MEMORY_TOTAL##*:}       #onservo la parte dopo gli ultimi duepunti


	#TRASFORMO DA STRINGHE A "NUMERI"
	TMP_TOT=${MEMORY_TOTAL:0:(-3)}     #memoria totale come numero
	TMP_FREE=${MEMORY_AVAIABLE:0:(-3)} #memoria libera come numero
	TMP_CACHED=${MEMORY_CACHED:0:(-3)} #memoria uasta per la cache come numero
	TMP_BUFFER=${MEMORY_BUFFER:0:(-3)} #memoria usata per i buffer come numero


	#Calcolo della memoria occupata (memoria totale - memoria libera ) + memor
	MEMORY_BUSY=$((TMP_TOT-TMP_FREE))

	#Calcolo della memoria occcupata da buffers e roba cached
	MEMORY_BUFF_CACHE=$((TMP_BUFFER+TMP_CACHED))

	#Calcolo della memoria occupata, senza contare quella dei buffer e cached
	MEMORY_USED=$((MEMORY_BUSY-MEMORY_BUFF_CACHE))
}
#-----------------------------------------------------------------------------------------------------------------------------

function stampaInfo {
	echo "************************************************"

	echo "                  [MEMORY]"
	echo "Total -------->$MEMORY_TOTAL"
	echo "Free --------->$MEMORY_AVAIABLE"
	echo "Total busy ---> $MEMORY_BUSY kB"
	echo "Busy (used) --> $MEMORY_USED kB"
	echo "Buff/Cached --> $MEMORY_BUFF_CACHE kB"

	echo "                  [CPU]"
	echo "Load over last minute    $CPU_LOAD_1m %"
	echo "Load over last 5 minute  $CPU_LOAD_5m %"
	echo "Load over last 10 minute $CPU_LOAD_10m %"

	echo "***********************************************"
}

#-----------------------------------------------------------------------------------------------------------------------------


function main {
	if [[ ! ( $COMMUNITY && $HOST && $ITERATIONS) ]]; then
		#se mancano parametri dico come si usa il tool e ritorno
		echo "usage: ./cpu_mem.sh [community] [host] [numIterations]"
		return 1
	fi
	
	#ciclo di 5 iterazioni per richiedere le informazioni tramite snmpd
	N=0
	while [[ $N<$ITERATIONS ]] ; do
		getMemInfo
		getCpuInfo
		stampaInfo
		N=$((N+1))
		sleep 5
	done
}

#----------------------------------------------------------------
#MAIN:
COMMUNITY=$1
HOST=$2
ITERATIONS=$3
main
#---------------------------------------------------------------





