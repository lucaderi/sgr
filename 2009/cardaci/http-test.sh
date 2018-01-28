#!/bin/bash

TMP=`tempfile`
./my-pcap -c $TMP
sudo ./my-pcap -ieth0 -fr$TMP -w80
