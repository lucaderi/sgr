#!/bin/bash

sniff_time=30

if [[ $# != 1 ]]; then
    echo "missing interface $#"
    echo "[sudo] ./test.sh interface"
    exit 1
fi

python3 HTTPMonitor.py -t $sniff_time -i $1 -r &
pid=$!
python3 HTTPMonitor_test.py

wait $pid
