#!/bin/bash
devc=""
collector=""
/sbin/ifconfig -a | grep -i 'UP,BROADCAST,RUNNING' | while IFS=' ' read -r dev flags mtu bytes
do
    if [ "$devc" = "" ] ; then 
        devc=${dev%':'}        
        /sbin/ifconfig "$devc" | grep -i 'inet6' | while IFS=' ' read -r prot ip pref len scope id
        do
            if [ "$collector" = "" ] ; then
                collector="$ip"     
                ./InMon_Agent-6.4/sflsp -d "$devc" -P -s 10 -A \'"$ip"\' -C \'"$collector"\' -c 5555 &                
            fi            
        done
    fi
done
./sflowtoinflux
