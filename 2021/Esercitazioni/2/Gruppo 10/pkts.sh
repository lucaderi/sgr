font=""
# Decommentare se usate Windows
#font='DEFAULT:13:c:/windows/fonts/Corbel.ttf'

# Valori di default per step e rows
step=5
rows=60

# Controlla che sia stato passato l'argomento
if [ $# = 0 ]; then
    echo 'Usage: ./pkts.sh interface [-s step] [-r rows]'
    #sleep 2
    exit
fi

# Legge il primo argomento
if [[ $1 = -* ]]; then
    echo 'Usage: ./pkts.sh interface [-s step] [-r rows]'
    #sleep 2
    exit
fi

interface=$1
shift

# Legge le opzioni
while getopts ":s:r:" opt; do
    case ${opt} in
    s ) if ! [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
            echo "$opt: l'argomento deve essere un intero"
            #sleep 2
            exit
        fi
        if [ "$OPTARG" -lt 1 ]; then
            echo "$opt: l'argomento deve essere maggiore o uguale a 1"
            #sleep 2
            exit
            fi
        step=$OPTARG;;
    r ) if ! [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
            echo "$opt: l'argomento deve essere un intero"
            #sleep 2
            exit
        fi
        if [ "$OPTARG" -lt 1 ]; then
            echo "$opt: l'argomento deve essere maggiore o uguale a 1"
            #sleep 2
            exit
        fi
        rows=$OPTARG;;
    : ) echo "$opt: argomento non presente"
        #sleep 2
        exit;;
    * ) echo 'Usage: ./pkts.sh interface [-s step] [-r rows]'
        #sleep 2
        exit;;
    esac
done

shift $(($OPTIND-1))

# Determina ifIndex (index) in base al nome dell'interfaccia
descr=$(snmpwalk -c public -v 1 localhost ifDescr | cut -f 4- -d ' ')
declare -i i=0
declare -i index=0
while IFS='\n' read line; do
    i=i+1
    if [[ "${line: -1}" == $'\r' ]]; then
        if [ "${line::-1}" = "$interface" ]; then
            index=i
            break
        fi
    else
        if [ "$line" = "$interface" ]; then
            index=i
            break
        fi
    fi
done <<< "$descr"

# Termina l'esecuzione se l'interfaccia non è stata trovata
if [ $index = 0 ]; then
    echo 'Interfaccia non trovata'
    # Stampa le interfacce disponibili
    echo 'Scegliere una tra le seguenti interfacce:'
    echo "$descr"
    #sleep 2
    exit
fi

# Crea il database
heartbeat=$(($step*2))
rrdtool create measurement.rrd --step $step \
DS:inUcastPkts:COUNTER:$heartbeat:0:4294967295 \
DS:outUcastPkts:COUNTER:$heartbeat:0:4294967295 \
DS:inNUcastPkts:COUNTER:$heartbeat:0:4294967295 \
DS:outNUcastPkts:COUNTER:$heartbeat:0:4294967295 \
DS:inDiscards:COUNTER:$heartbeat:0:4294967295 \
DS:outDiscards:COUNTER:$heartbeat:0:4294967295 \
DS:inErrors:COUNTER:$heartbeat:0:4294967295 \
DS:outErrors:COUNTER:$heartbeat:0:4294967295 \
DS:inUnknownProtos:COUNTER:$heartbeat:0:4294967295 \
RRA:AVERAGE:0.5:1:$rows

# Legge i valori ogni step secondi per step*rows secondi
p25=$(($rows/4))
p50=$(($rows/2))
p75=$(($p25 + $p50))

seconds=$(($step*$rows))
minutes=$(($seconds/60))
hours=$(($minutes/60))

minutesremaining=$(($minutes % 60))

if [ $minutes = 0 ]; then
	echo "Tempo stimato: meno di un minuto"
    minutes=1

else
	echo "Tempo stimato: $hours h $minutesremaining m"
	
fi

echo "$(date +"%H:%M") lettura dei valori in corso..."
declare -i t=0
echo '0%...'

while [ $t != $rows ]; do
    values=$(snmpget -v 1 -c public localhost ifInUcastPkts.$index ifOutUcastPkts.$index ifInNUcastPkts.$index \
    ifOutNUcastPkts.$index ifInDiscards.$index ifOutDiscards.$index ifInErrors.$index ifOutErrors.$index ifInUnknownProtos.$index)
    IFS=$'\n' read -r -d '' -a values_arr <<< "$values"
    inUcastPkts=$(cut -f 4 -d ' ' <<< ${values_arr[0]})
    outUcastPkts=$(cut -f 4 -d ' ' <<< ${values_arr[1]})
    inNUcastPkts=$(cut -f 4 -d ' ' <<< ${values_arr[2]})
    outNUcastPkts=$(cut -f 4 -d ' ' <<< ${values_arr[3]})
    inDiscards=$(cut -f 4 -d ' ' <<< ${values_arr[4]})
    outDiscards=$(cut -f 4 -d ' ' <<< ${values_arr[5]})
    inErrors=$(cut -f 4 -d ' ' <<< ${values_arr[6]})
    outErrors=$(cut -f 4 -d ' ' <<< ${values_arr[7]})
    inUnknownProtos=$(cut -f 4 -d ' ' <<< ${values_arr[8]})
    #echo "inUcastPkts outUcastPkts inNUcastPkts outNUcastPkts inDiscards outDiscards inErrors outErrors inUnknownProtos"
    #echo "$inUcastPkts $outUcastPkts $inNUcastPkts $outNUcastPkts $inDiscards $outDiscards $inErrors $outErrors $inUnknownProtos"
    rrdtool update measurement.rrd N:$inUcastPkts:$outUcastPkts:$inNUcastPkts:$outNUcastPkts:$inDiscards:$outDiscards:$inErrors:$outErrors:$inUnknownProtos

    t=t+1
    sleep $step

    case $t in
        $p25 ) echo '25%...';;
        $p50 ) echo '50%...';;
        $p75 ) echo '75%...';;
        $rows ) echo '100%';;
        * ) ;;
    esac

done

echo "Lettura dei valori terminata"

# Creazione del grafico
echo "Creazione del grafico in corso..."

if [ -z "$font" ]; then
    rrdtool graph packets.png --start -"$hours"h"$minutesremaining"m \
    DEF:inUP=measurement.rrd:inUcastPkts:AVERAGE \
    DEF:outUP=measurement.rrd:outUcastPkts:AVERAGE \
    DEF:inNUP=measurement.rrd:inNUcastPkts:AVERAGE \
    DEF:outNUP=measurement.rrd:outNUcastPkts:AVERAGE \
    DEF:inD=measurement.rrd:inDiscards:AVERAGE \
    DEF:outD=measurement.rrd:outDiscards:AVERAGE \
    DEF:inE=measurement.rrd:inErrors:AVERAGE \
    DEF:outE=measurement.rrd:outErrors:AVERAGE \
    DEF:inUnkP=measurement.rrd:inUnknownProtos:AVERAGE \
    CDEF:g1=inUP,inNUP,+ \
    CDEF:g2=inUP,inNUP,+,inD,+,inUnkP,+,inE,+ \
    CDEF:g3=outUP,outNUP,+,outE,-,outD,- \
    LINE:g1#ff0000:'Delivered packets to the next higher protocol layer' \
    LINE:g2#00ff00:'Received packets' \
    LINE:g3#0000ff:'Transmitted packets'
	
	open ./packets.png
else
    rrdtool graph packets.png --font "$font" --start -"$hours"h"$minutesremaining"m \
    DEF:inUP=measurement.rrd:inUcastPkts:AVERAGE \
    DEF:outUP=measurement.rrd:outUcastPkts:AVERAGE \
    DEF:inNUP=measurement.rrd:inNUcastPkts:AVERAGE \
    DEF:outNUP=measurement.rrd:outNUcastPkts:AVERAGE \
    DEF:inD=measurement.rrd:inDiscards:AVERAGE \
    DEF:outD=measurement.rrd:outDiscards:AVERAGE \
    DEF:inE=measurement.rrd:inErrors:AVERAGE \
    DEF:outE=measurement.rrd:outErrors:AVERAGE \
    DEF:inUnkP=measurement.rrd:inUnknownProtos:AVERAGE \
    CDEF:g1=inUP,inNUP,+ \
    CDEF:g2=inUP,inNUP,+,inD,+,inUnkP,+,inE,+ \
    CDEF:g3=outUP,outNUP,+,outE,-,outD,- \
    LINE:g1#ff0000:'Delivered packets to the next higher protocol layer' \
    LINE:g2#00ff00:'Received packets' \
    LINE:g3#0000ff:'Transmitted packets'
	
	start file://%CD%/packets.png
fi

echo "$(date +"%H:%M") processo terminato"
#sleep 5
