#!/bin/bash
echo "Begin test"

for ((i=0; i<=10; i+=1)); do
	echo ""
	nping -c 1 --tcp -p 80,433 scanme.nmap.org google.com github.com unipi.it
	
	sleep $((1 + RANDOM % 4))
	
done


