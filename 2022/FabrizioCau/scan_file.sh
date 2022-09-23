#!/bin/bash

# 
# Pcap Malware Checker (SUPPORT SCRIPT)
# (do not run manually) 
#
# Author: Fabrizio Cau
#
# Description: 
#  This script uploads the file passed as argument to Virus Total 
#  for check and print information about its scan report
#

# config parameters 
con_to=1 # VirusTotal curl connection timeout
wait_until_scan_complete=3 # time to wait until scan is completed
debug_mode=1 # when enabled prints information during wait-on-queued and on clean files 

#checks if required tools are installed
check_dependency() {
    if [[ ! $(command -v jq) ]]; then
        echo "To run this tool you need to install jq"
        exit 4
    elif [[ ! $(command -v curl) ]]; then
        echo "To run this tool you need to install curl"
        exit 4
    fi
}

check_dependency


# prints help how-to-use information
Help() {
    echo "Support script for Pcap Malware Checker (malcheck.sh)"
    echo "See https://github.com/caufab/pcap-malware-checker"
    echo "This support script checks if a file contains malicious code"
    echo "Uses VirusTotal API (https://www.virustotal.com)"
    echo ""
    echo "Must be used with file path and API key parameter at least"
    echo ""
    echo "Usage: scan_file [options] ..."
    echo ""
    echo "  -f <file>      file path"
    echo "  -k <key>       VirusTotal API Key (64 alphanumeric digit)"
    echo "  -h -help       shows help info"
}

# flags 
APIKEY_OK=0
FILE_OK=0

# base url from Virus Total
URL="https://www.virustotal.com/api/v3/files"


while getopts ":f:k:help:" FLAG; do
    case ${FLAG} in
        h | help )  # print help 
            Help
            exit 0;;
        f )         # store pcap file path if file exists
            FILE="$OPTARG"
            if [ ! -f $PCAP_PATH ]; then 
                echo "$PCAP_PATH is not a file"
                exit 2
            else 
                FILE_OK=1
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
if [ $((FILE_OK+APIKEY_OK)) -lt 2 ]; then
    echo "Missing arguments: type -help or -h to view available commands"
    exit 1
fi


# checks if http response code is an error code and prints details
response_check() {
    local urltmp="$1"    
    if [[ $urltmp == "000" ]]; then 
        echo "Call to VirusTotal failed: no answer was received"
        exit 1        
    fi
    http_code=${urltmp: -3}
    http_content=${urltmp%???}
    if [[ $err_code -ge 400 ]]; then
        err_msg=$(echo "$http_content" | jq -r '.error.message' )
        echo "Call to VirusTotal failed: $err_msg"
        exit 1
    fi
}


# get file size
FILE_SIZE=$(wc -c "$FILE" | awk '{print $1}' )

if [[ $FILE_SIZE -gt 33554431 ]]; then
    # if file is bigger than 32MB it retrieves upload url from Virus Total
    URL_tmp=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/upload_url" --header "x-apikey: $VT_APIKEY" --connect-timeout $con_to -w "%{http_code}")   
    response_check "$URL_tmp"
    json_content=${URL_tmp%???}
    URL=$(echo $json_content | jq -r .data)
fi


# uploads the file in Virus Total for scan and extracts the analysis id
URL_tmp=$(curl -s --request POST --url "$URL" --header "x-apikey: $VT_APIKEY" --form "file=@$FILE" --connect-timeout $con_to -w "%{http_code}")
response_check "$URL_tmp"
json_content=${URL_tmp%???} # removes last 3 digits (http_code)

# parses id from json content received
FILEID=$(echo "$json_content" | jq -r '.data.id' )

Attempt=1

SCAN_RES_STAT="notyetstarted" # dummy value to enter loop
while [ "$SCAN_RES_STAT"  != "completed" ]; 
do
    URL_tmp=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/analyses/$FILEID" --header "x-apikey: $VT_APIKEY" --connect-timeout $con_to -w "%{http_code}")
    response_check "$URL_tmp"
    json_content=${URL_tmp%???}
    
    # parses report status from json content received
    SCAN_RES_STAT=$(echo "$json_content" | jq -r '.data.attributes.status')

    # if debug mode is on prints information about waiting and attempts 
    if [[ $debug_mode -eq 1 ]]; then
        echo "Checking file $FILE: [$SCAN_RES_STAT] (Attempt after: $Attempt s)"
        Attempt=$((Attempt+wait_until_scan_complete))
    fi
    # waits until next attempt
    if [[ "$SCAN_RES_STAT"  != "completed" ]]; then
        sleep $wait_until_scan_complete &
        wait $!
    fi
done


# now it's completed or script ended, malicious result can be parsed
SCAN_RES_MAL=$(echo $json_content | jq -r '.data.attributes.stats.malicious')


# if report shows malicious results then print its count
if [[ $SCAN_RES_MAL -ne 0 ]]; then
    MAL_FILES=$((MAL_FILES+1))
    echo "The file $FILE [$FILE_SIZE bytes] contains malicious code in $SCAN_RES_MAL reports"
elif [[ $debug_mode -eq 1 ]]; then  # if debug mode is on prints if file is safe
    echo "File $FILE is clean"
fi



