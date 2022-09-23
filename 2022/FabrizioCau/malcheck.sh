#!/bin/bash

#
# Pcap Malware Checker (MAIN SCRIPT)
# 
# Author: Fabrizio Cau
# 
# Description: 
#  This tool takes a pcap file path and a VirusTotal API key,
#  searches for executable files trasmitted via http flow
#  and sends each of them to scan_file.sh for malicious code check
#

#checks if required tools are installed
check_dependency() {
    if [[ ! $(command -v jq) ]]; then
        echo "To run this tool you need to install jq"
        exit 4
    elif [[ ! $(command -v curl) ]]; then
        echo "To run this tool you need to install curl"
        exit 4
    elif [[ ! $(command -v tshark) ]]; then
        echo "To tun this tool you need to install tshark"
        exit 4
    elif [[ ! -f "./scan_file.sh" ]]; then
        echo "To run this tool you need support script scan_file.sh in the same directory of this tool"
        exit 4
    fi
}

check_dependency

# prints help how-to-use information
Help() {
    echo "Pcap Malware Checker"
    echo "See https://github.com/caufab/pcap-malware-checker"
    echo "Tool that checks for malicious executable files inside HTTP flow captured in a pcap file "
    echo "Uses VirusTotal API to check each file (https://www.virustotal.com)"
    echo ""
    echo "Must be used with pcap file path and API key parameter at least"
    echo ""
    echo "Usage: ./malcheck [options] ..."
    echo ""
    echo "  -f <file>      pcap file path [required]"
    echo "  -k <key>       Virus Total API Key (64 alphanumeric digit) [required]"
    echo "  -h -help       shows help info"
}


APIKEY_OK=0
PCAP_FILE_OK=0
MAL_FILES=0 # number of infected files
protocol="http" # tshark will extract this protocol flow 
tmp_dir="./malchecker_tmp" # directory used to place extracted files

# on script termination delete all files
trap "rm -rf $tmp_dir/*" INT

while getopts ":f:k:help:" FLAG; do
    case ${FLAG} in
        h | help )  # print help 
            Help
            exit 0;;
        f )         # store pcap file path if file exists
            PCAP_PATH="$OPTARG"
            if [ ! -f $PCAP_PATH ]; then 
                echo "$PCAP_PATH is not a file"
                exit 2
            else 
                PCAP_FILE_OK=1
            fi;;
        k )         # store VT api keyand check integrity 
            if [[ $OPTARG =~ ([0-9a-z]{64}) ]]; then
                VT_APIKEY="$OPTARG"
                APIKEY_OK=1
            else
                echo "Invalid API key: $OPTARG"
                exit 1
            fi;;
        * )         # print error
            echo "Invalid arguments: type -help or -h to view available commands"
            exit 1
   esac
done

# checks if requirements are reached 
if [ $((PCAP_FILE_OK+APIKEY_OK)) -lt 2 ]; then
    echo "Missing arguments: type -help or -h to view available commands"
    exit 1
fi


# create/clean temp directory
if [ -d "$tmp_dir" ]; then 
    rm -rf $tmp_dir/*
else 
    mkdir $tmp_dir
fi


# extracts files from the pcap file
tshark -Q -r $PCAP_PATH --export-objects $protocol,$tmp_dir


# checks if tshark has extracted any file 
if [ -z "$(ls -A $tmp_dir)" ]; then
    echo "HTTP flow does not contain any files"
    exit 0
fi

# removes all non-executable files
file $tmp_dir/* -F / | grep -v -F "executable" | cut -f1-3 -d$'/' | xargs -I{} rm {}

# checks if tshark has extracted any executable file
if [ -z "$(ls -A $tmp_dir)" ]; then
    echo "HTTP flow does not contain executable files"
    exit 0
fi


echo "Scan result:"

# if executable files are found, find them and send each one of them to scan_file.sh with the VT api key
find $tmp_dir -type f -exec ./scan_file.sh -f {} -k $VT_APIKEY \;

echo "End of scan"

# remove files
rm -rf $tmp_dir/*
# end