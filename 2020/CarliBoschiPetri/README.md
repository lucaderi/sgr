# MalwareDetection

This tool uses pyshark library and a Python implementation of the HyperLogLog counter algorithm to analyze a .pcap file and check if a specific host is infect.


## Prerequisites

First of all, you have to type the following line on your shell in order to install and manage the other software packages, written in Python, used by this tool (for more info click [here]([https://linuxize.com/post/how-to-install-pip-on-ubuntu-18.04/](https://linuxize.com/post/how-to-install-pip-on-ubuntu-18.04/))).

```bash
$ sudo apt install python3-pip
```
Then, you have to install on Ubuntu:

 - [tshark](https://zoomadmin.com/HowToInstall/UbuntuPackage/tshark): allows you to sniff traffic network, read or capture packets
	  ```bash
	$ `sudo apt-get install -y tshark`
	```
 - [pyshark](https://zoomadmin.com/HowToInstall/UbuntuPackage/tshark): Python wrapper for tshark
	 ```bash
	$ sudo pip3 install pyshark
	```
 - [hyperloglog](https://pypi.org/project/hyperloglog/): Python implementation of the HyperLogLog and Sliding HyperLogLog cardinality counter algorithms
	 ```bash
	$ pip3 install hyperloglog
	```

<br>

## Usage
```bash
$ python3 MalwareDetection.py [-h] [-v] [-p FILENAME] [-sIP NUM_IP] [-sPS NUM_PORTSSRC] [-sPD NUM_PORTSDST] [-t TIME]
```
<br>


**Arguments:**
| Flag     | Description    | 
| :------------- | :----------: | 
|  -h, --help | Show help message  | 
|  -v | Enable verbose mode  |
| -p      | Name of .pcap file to analyze (mandatory flag) | 
| -sIP    | Different IPdst threshold (default: 30) | 
| -sPS    | Different source ports threshold (default: 50) | 
| -sPD    | Different destination ports threshold (default: 50) | 
| -t      | Step in seconds in which .pcap file is divided (default: 30s) | 

<br>

## Examples

**Output standard**
```bash
$ g: python3 MalwareDetection.py -p normal_traffic_and_port_scan.pcapng -t 10


Analyzing normal_traffic_and_port_scan.pcapng ...
This tool analyzes file using 10 seconds intervals

...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...

Vulnerability detected:          (1 IP --> N IP)
Vulnerability detected: (1 IP, 1 PORT  --> 1 IP, N PORTS)

Analysis terminated
Closing file normal_traffic_and_port_scan.pcapng
```
  <br>
  <br>
  
  **Output with verbose mode enabled**
  ```bash
g: python3 MalwareDetection.py -p normal_traffic_and_port_scan.pcapng -t 200 -v

Analyzing normal_traffic_and_port_scan.pcapng ...
This tool analyzes file using 200 seconds intervals

...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...
...Analyzing...

+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
| Type of attack:    1 IP -> N IP
|      Problem:      probable source host infection
|    Description:    192.168.1.7 is contacting 47 different hosts
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                    

+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
| Type of attack:    1 IP, 1 PORT -> 1 IP, N PORTS
|       Problem:     probable port scanning on 192.168.1.1
|     Description:   192.168.1.7::42919 is contacting host 192.168.1.1 on 3226 different ports
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                    

Analysis terminated ... 
Closing file normal_traffic_and_port_scan.pcapng
```
