
#!/bin/bash

logs="/var/lib/docker/volumes/$(YOUR_COWRIE_VOLUME_ID)/_data/log/cowrie/cowrie.json"
shared="/media/sf_ctrl1/syncedLog.json"
echo "Log sync started"
while true; do
 rsync -avq "$logs" "$shared"
 sleep 15
done
