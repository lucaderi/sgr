#!/bin/bash

while getopts "h" flag; do
    case $flag in
        h)
            nohup python3 honeySimCowrie.py > /dev/null 2>&1 &
            background_process_pid=$!

            nohup python cowriePrometheus.py > /dev/null 2>&1 &
            cowrie_prometheus_pid=$!

            exit 0
            ;;
        *)
            echo "Invalid flag"
            exit 1
            ;;
    esac
done

cleanup() {
    rm ./last_line_prom.txt
    touch ./last_line_prom.txt
    rm syncedLog.json
    touch syncedLog.json
    if [[ -n $background_process_pid ]]; then
        kill "$background_process_pid"
    fi
    if [[ -n $cowrie_prometheus_pid ]]; then
        kill "$cowrie_prometheus_pid"
    fi
}

trap cleanup EXIT

nohup python3 honeySimCowrie.py > /dev/null 2>&1 &
background_process_pid=$!

python cowriePrometheus.py
