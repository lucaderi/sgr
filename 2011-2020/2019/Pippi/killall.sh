#!/bin/bash
pgrep sflsp | while read -r pid 
do
	echo "$pid"
	kill -9 "$pid"
done