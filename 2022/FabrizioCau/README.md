# Pcap Malware Checker
Given a packet capture file it checks for malwares in executable files found in http flow

## Author
Fabrizio Cau ([f.cau1@studenti.unipi.it](mailto:f.cau1@studenti.unipi.it))

Project proposed by professor [Luca Deri](http://luca.ntop.org/) for the course of Gestione di Reti 21/22 @ University of Pisa

## Description
The main script first run a simple checks on all required scripts and tools, then using TShark [(man page)](https://www.wireshark.org/docs/man-pages/tshark.html) extracts all files transiting in the http flow captured in the pcap file and keeps only executable ones. On each of them it calls the support script.

NOTE: the search of executable files is made using `file` command, which prints a file type description. This output is then parsed by a few other commands to remove those files whose type does not contain "executable" in it.
Other choices made initially were to check file extension or unix permission to execute (+x) but they turned out to be too weak.

The support script is stand-alone which means it can be run manually for checking any file, for this reason it first checks for all dependecy. 
It then makes two curl call to VirusTotal: one for uploading the file, the next to retrieve scan report. 
(if file size is >32MB it first gets a dedicated url)

Each curl response contains a json string from the website and a tail with 3 digit http response status. Each of them are parsed: from the status code the script can see if request was received and then gets the status of the scan report (with number of positive malware checks). Otherwise it prints error details.

NOTE: Using free account VT API, after file upload, the report status is often "*queued*": this means it's report is not ready yet. In this case the script keeps checking every *`n`* seconds (see [Config](https://github.com/caufab/pcap-malware-checker/edit/main/README.md#config)) until it is *completed*
Also, if the daily/monthly quota of API are reached the report status shown might be "*null*", in that case it's convenient to interrupt the tool `(CTRL+C)` and to try again later

At the end of the scan, the support script prints if the file contains malicious code and all files extracted from the pcap are removed when the main tool ends.

Uses [VirusTotal](https://www.virustotal.com) for file analysis 

### Files description
- `malcheck.sh`: main script, takes pcap file path and VT API token (type ./malcheck.sh -help for more info)

- `scan_file.sh`: support script called by main script (can run stand-alone)

## Requirements:
- `tshark`
- `jq`
- `curl`
- Internet connection 
- VirusTotal API token

NOTE: This tool creates a directory named "malchecker_tmp" next to the main tool. If a directory with the same name already exists, its content will for sure be erased.

### Obtain requirements
Make sure you have all required tools installed: you can check this by launching this tool with `./malcheck.sh` in your unix shell. 
If something is missing just type the tool name in the shell and you'll receive info on how to install them.

To obtain VirusTotal API token go to https://www.virustotal.com/gui/my-apikey, sign up and copy your API key

## Usage
To launch this tool in the shell, type: 
```
./malcheck.sh -f <pcap file path> -k <virustotal api key>
```

To print informazion and usage options in shell, type:
```
./malcheck.sh -h
```


## Configuration
Config parameters can be changed from inside each script, each one has its own description in a comment


## Test check 
At this [link](https://www.malware-traffic-analysis.net/2022/01/12/index.html) there si a zipped pcap file named 
```
2022-01-12-IcedID-with-Cobalt-Strike-and-DarkVNC.pcap.zip
```

Download it, extract the pcap and use its path when launching the tool

This pcap contains 5 executable files and two of them (.exe) should be recognised as malwares, and the output (in debug mode) should be like this:

![pcap_malcheck_screen](https://user-images.githubusercontent.com/113622800/191819351-63f77b3c-e6c5-4cc7-a89d-4f0e01302c59.png)


## Notes
This tool was made under Ubuntu 18.04 via WSL
