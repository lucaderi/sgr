#!/bin/bash
shared="/media/sf_ctrl1/syncedLogDion.json"
while true; do
 date=$(date +'%Y-%m-%d')
 echo "dionaea.json.$date"
 logs="/opt/dionaea/var/log/dionaea/json/dionaea.json.$date" 
 rsync -avq "$logs" "$shared"
 sleep 15
done
