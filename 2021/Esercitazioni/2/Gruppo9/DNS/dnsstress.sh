#!/bin/bash

filename='./dga.txt'
while read line; do
	line=${line%$'\r'}  
	nslookup $line
	sleep 1
done < $filename