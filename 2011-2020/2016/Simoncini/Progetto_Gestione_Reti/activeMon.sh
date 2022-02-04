#!/bin/bash

source header.sh

ip=$1
delta=$2
tol=$3
dimCache=7
can=1
qt=$#

test1="8.8.8.8"

#Controllo i parametri
end=0

if [ $# -eq 0 ]; then
  echo "Usage: ./activeMon [-h] <ip> <time> <accuracy>
  Options:
        -h          Display the help
  "
  exit
fi

if [ $# -eq 1 ]; then
  checkHelp $1
  exit
fi

checkPar $1 $2 $3
if [ $can -eq 0 ]; then
  echo "Wrong Parameters, check manpage typing 'man ./activeMon'"
  exit
fi




echo "Initializing ActiveMon.."
#sleep 1

echo "Ping address = "$1
echo "Lapse = "$2
echo "Fault Tolerance = "$3

j=0
googlePing=0
res=0
fixMin=2000
min=2000
m=0
dimArrayStat=7
perc=0
cond=0

initColor

#$j -lt 10
while [ true ]
do
  logFile="Logs/log$j"
  historyFile="Logs/ping_History_log$j.txt"
  stato=0
  succ=0
  exp=0
  fail=0


  #Effettuo un ping di test su un DNS affidabile
  googlePing=$(pingIst $test1)

  #Eseguo la funzione che effettua i ping verso l'IP richiesto e ne estrae
    #i risultati
  pingFun $1 $2 $j > $logFile
  #pingCheck $logFile
  echo "Iter $j) Ping Successful= "$succ" Ping Failed= "$fail
  tot=$(($succ+$fail))

  #Converto il valore in percentuale di successo e lo testo
  perc=$(echo "scale=2;$succ/$tot" | bc)
  perc=$(echo "scale=2;$perc*100" | bc)
  perc=$(echo "scale=0;$perc" | bc)

  #Popolo gli array Cache
  ind=$(($j%$dimCache))
  estraiVal $historyFile
  minArray[$ind]=$min
  maxArray[$ind]=$max
  avgArray[$ind]=$avg
  stdevArray[$ind]=$stdev
  if [ $fail -eq $tot ]; then
    min=2000
  fi

  #Aggiorno fixMin che si avvicina sempre di più al valore di ping reale
   #dell'IP considerato in assenza di fattori esterni
  cond=$(echo $fixMin'>'$min | bc -l )
  #echo "fixMin= "$fixMin" MIN= "$min
  #echo "COND= "$cond
  if [ $cond -eq 1 ]; then
    #echo "MIN UPDATED: "$fixMin" -> "$min
    fixMin=$min
  fi

  #Controllo lo stato della rilevazione e lo inserisco nell'array di stati
  #echo "Percentuale successo= "$perc
  var=$(echo $perc'<'$3 | bc -l)
  statusColoring $3

  statusArray[$m]=$stato

  #Effettuo verifiche sull'array
  if [[ $stato -eq 2 ]]; then
    report
  else
    detectAnomaly $m
  fi


  j=$((j + 1))
  j=$(($j%600))
  m=$((($m+1)%($dimArrayStat)))

done

#echo "Minimo storico= "$fixMin
