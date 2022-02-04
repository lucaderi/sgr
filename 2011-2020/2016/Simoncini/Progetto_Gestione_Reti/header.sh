#!/bin/bash

is_int() {
  local var=$1
  if [[ $var =~ ^-?[0-9]+$ ]] ; then
    echo $var
  else
    echo -1
  fi

}

displayHelp(){

    echo "Usage: ./activeMon [-h] <ip> <time> <accuracy>
    
Help: Test the response time of an Ip over a network
      <Ip>: IPv4 address
      <time>: Positive integer greater than 0
      <accuracy>: Positive integer greater than 15 and minor than 100

Options:
      -h          Display this help
"

}

checkHelp(){

  while getopts ":h" opt; do
  case $opt in
    h)
      displayHelp >&2
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      displayHelp
      ;;
  esac
done

}

valid_ip(){
    local  ip=$1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi

}

checkPar(){

  stat=1

  if [ $qt -ne 3 ] ; then can=0
    echo "ERROR: EXACLTY three parameters required!!"
    echo "check manpage at 'man ./activeMon' for further informations"
    exit
  fi
  valid_ip $1

  if [ $stat -eq 1 ]; then can=0
  echo "ERROR: (Param 1) Invalid IP, provide an IPv4 address!!"
  can=0
  fi

  local ok=$(is_int $2)

  if [ $ok -eq -1 ] || [ $ok -lt 1 ]; then can=0
  echo "ERROR: (Param 2) TimeLapse MUST be an integer greater than 0!!"
  can=0
  fi

  ok=$(is_int $3)

  if [ $ok -eq -1 ] || [ $ok -gt 100 ] || [ $ok -lt 15 ]; then can=0
  echo "ERROR: (Param 3)  Accuracy MUST be an integer greater than 15 and minor than 100!!"
  can=0
  fi


}

pingFun(){
  local file="Logs/ping_History_log$3.txt"


  date > $file
  ping -c $2 $1 >> $file

  local i=1
  local count=0

  succ=$(grep "packets" $file | awk '{print $4}')
  fail=$(($2-$succ))

  echo "Successful:"$succ
  echo "Expired:"$exp
  echo "Failed:"$fail


}

pingIst(){
  local file="temp.txt"

  ping -c1 $1 > $file

  local data=0

  while read p; do
    for token in $p
    do
      local s=${token:0:5}
      if [ "$s" = "time=" ]; then
        data=${token:5:6}
      fi
      i=$((i + 1))
    done
  done < $file

  rm -f $file

  echo $data
}

pingCheck(){
  local file=$1
  local ok=0
  while read p; do
    for token in $p
    do
      local s=${token:0:6}
      local t=${token:0:7}
      local u=${token:0:6}
      pin=${token:0:5}
      if [ "$s" = "Succes" ]; then
        succ=${token:11:1}
      fi
      if [ "$t" = "Expired" ]; then
        exp=${token:8:1}
      fi
      if [ "$u" = "Failed" ]; then
        fail=${token:7:1}
      fi
    done
  done < $file

}

estraiVal(){

  local data=$(tail -1 $1)

  IFS='=' read -r useless stringData <<< "$data"
  IFS='/' read -r min stringData <<< "$stringData"
  IFS='/' read -r max stringData <<< "$stringData"
  IFS='/' read -r avg stringData <<< "$stringData"
  IFS=' ' read -r stdev stringData <<< "$stringData"

}

initColor(){
  local i=0
  while [  $i -lt $dimArrayStat ]; do
    statusArray[$i]=0
    i=$((i+1))
  done
}

statusColoring(){
  ent=15
  if [ $var -eq 1 ]; then
    newThresh=$(echo "scale=2;$1-$ent" | bc)
    var=$(echo $perc'<'$newThresh | bc -l)
    if [ $var -eq 1 ]; then
      #echo "Nero!!"
      stato=2
    else
      #echo "Grigio!"
      stato=1
    fi

    #echo "Soglia= "$1" SogliaGrigio= "$newThresh" Var= "$var


  fi
}

report(){
  echo "Anomalia!Effettuo report"
  str=$(date)
  IFS='CE' read -r title useless <<< "$str"
  local file="Anomalia_$title" #problema
  local newFile=${historyFile/Logs\//""}

  cp $historyFile "Reports/"
  mv "Reports/"$newFile "Reports/$file"

}

detectAnomaly(){
  local count=0
  local acc=3
  local p=$1
  local stop=$((($1-4)%($dimArrayStat)))
  local i=$stop

  while [  $i -ne $p ]; do
    if [[ ${statusArray[$p]} -eq 1 ]]; then
      count=$((count+1))
    fi
    i=$((($i+1)%($dimArrayStat)))
  done

  if [[ $count -gt 2 ]]; then
    report
    echo "Situazione Anomala"
  fi

}
