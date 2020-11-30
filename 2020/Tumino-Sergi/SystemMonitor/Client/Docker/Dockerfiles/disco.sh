#!/bin/bash

sysbench fileio --file-total-size=5G --file-test-mode=rndrw --time=1 --max-requests=0 prepare
sysbench fileio --file-total-size=5G --file-test-mode=rndrw --time=1 --max-requests=0 run
sysbench fileio --file-total-size=5G --file-test-mode=rndrw --time=1 --max-requests=0 cleanup