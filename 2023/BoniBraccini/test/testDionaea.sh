#!/bin/bash

cleanup() {
    if [[ -n $background_process_pid ]]; then
        kill "$background_process_pid"
    fi
}

trap cleanup EXIT

nohup python demoFileDionaea.py > /dev/null 2>&1 &

background_process_pid=$!

python dionaeaPrometheus.py


