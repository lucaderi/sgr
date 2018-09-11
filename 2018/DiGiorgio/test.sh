#!/bin/bash

# autore: Alessandro Di Giorgio
# mail: a.digiorgio1@studenti.unipi.it

# avvia un server di prova
docker run  --rm --name=test-server -p 5201:5201 networkstatic/iperf3 -s &
sleep 1
# prendi l'indirizzo del server
serverAddr=$( docker inspect --format '{{ .NetworkSettings.IPAddress }}' test-server )
# avvia la sonda
python ./eBPFlow.py -d &
pid=$! # prendi il pid della sonda
sleep 3
# avvia un client di prova
docker run  -it --rm --name=test-client networkstatic/iperf3 -c $serverAddr
# interrompi la sonda
kill -s SIGINT $pid >/dev/null
# interrompi il sever
docker kill test-server >/dev/null
