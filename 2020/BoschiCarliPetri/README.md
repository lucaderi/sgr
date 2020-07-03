# MalwareDetection

This tool uses pyshark library and a Python implementation of the HyperLogLog counter algorithm to analyze a .pcap file and detect anomalies on hosts and other network devices.


## HyperLogLog

**Description**

A HyperLogLog is a probabilistic data structure used to count unique values as well as calculating the cardinality of a set. These values can be anything: in this tool we use this structure for counting different IP addresses and different ports.

Counting unique values normally requires to keep a support data structure that mantains all different values and grows proportionally to them.  The problem is that for large sets of data this structure could be too big and we have to scan it to verify the uniqueness of each value.
HyperLogLog algorithm solves this problem with a tradeoff between memory and precision, using a probabilistic data structure fixed in size and relative small. 
For example, it can estimate cardinalities of sets larger than 10^9 with a standard error of 2% using only 1.5 kilobytes of memory.

**How it works**

HyperLogLog algorithm is based on the probability to get a certain binary number.
If a random number is generated, the probability that it has n leading zeros is very low: 1/2^n; but if you generate 2^n random numbers, you expect that at least one of them will have n leading zeros, while the others will have less.  

If you have a list of N unique numbers and you don't know its exact length, you can estimate it using the probability of each number, represented in binary. When you find a number with n leading zeros, it has a probability of 1/2^n being generated, and therefore it is very likely that at least 2^n other numbers were generated before it. The length of the list will therefore be approximately 2^n.

For our specific problem we are interested in detect anomalies on .pcap files, so we use HyperLogLog to count the number of different IPs and ports. In our case, each IP is analyzed, it is represented in binary and only the number of leading zeros is kept.  An average is then made between the leading zeros of the various IPs: this average will be used to estimate the number of unique IPs found, always according to the previous reasoning.
<br>

## Idea of this tool

The purpose of the tool is to detect anomalies and some types of attacks, given a .pcap file.  
To do this, we have identified 3 main attacks to which we pay attention: they are detected through the use of some thresholds, chosen by the user ( they also have default values).
Counts are made on the number of different IPs and ports using a Python implementation of HyperLogLog, and if these counts exceed the threshold value, a possible attack is highlighted.

This tool detects the following types of attack:

 - **1 IP ---> N IPs**: in this case if N exceed the specific threshold, there is a probability that source IP is infect and it's trying to attack other devices on the network.
 - **1 IP, 1 PORT ---> 1 IP, N PORTS**: in this case if N exceed the specific threshold, there is a probable port scanning on destination IP.
 - **1 IP, N PORTS ---> 1 IP, 1 PORT**: in this case if N exceed the specific threshold, there is a probable attempt to access a specific service on destination IP too many times, from nay different source ports.

## Prerequisites

First of all, you have to type the following line on your shell in order to install and manage the other software packages, written in Python, used by this tool (for more info click [here](https://linuxize.com/post/how-to-install-pip-on-ubuntu-18.04/)).

```bash
$ sudo apt install python3-pip
```
Then, you have to install on Ubuntu:

 - [tshark](https://zoomadmin.com/HowToInstall/UbuntuPackage/tshark): allows you to sniff traffic network, read or capture packets
	  ```bash
	$ sudo apt-get install -y tshark
	```
 - [pyshark](https://github.com/KimiNewt/pyshark): Python wrapper for tshark
	 ```bash
	$ sudo pip3 install pyshark
	```
 - [hyperloglog](https://pypi.org/project/hyperloglog/): Python implementation of the HyperLogLog and Sliding HyperLogLog cardinality counter algorithms
	 ```bash
	$ sudo pip3 install hyperloglog
	```

<br>

## Usage
```bash
$ python3 MalwareDetection.py [-h] [-v] [-p FILENAME] [-sIP NUM_IP] [-sPS NUM_PORTSSRC] [-sPD NUM_PORTSDST] [-t TIME]
```
<br>


**Arguments:**
| Flag           | Description    | 
| :------------- | :----------: | 
|  -h, --help    | Show help message  | 
|  -v            | Enable verbose mode  |
| -p             | Name of .pcap file to analyze (mandatory flag) | 
| -sIP           | Different IPdst threshold (default: 30) | 
| -sPS           | Different source ports threshold (default: 50) | 
| -sPD           | Different destination ports threshold (default: 50) | 
| -t             | Step in seconds in which .pcap file is divided (default: 30s) | 

<br>

## Examples

**Output standard**
```bash
$ g: python3 MalwareDetection.py -p normal_traffic_and_port_scan.pcapng -t 10


Analyzing normal_traffic_and_port_scan.pcapng ...
This tool analyzes normal_traffic_and_port_scan.pcapng using 10 seconds intervals

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

Vulnerability detected:          (1 IP --> N IPs)
Vulnerability detected: (1 IP, 1 PORT  --> 1 IP, N PORTS)

Analysis terminated
Closing normal_traffic_and_port_scan.pcapng
```
  <br>
  <br>
  
  **Output with verbose mode enabled**
  ```bash
$ g: python3 MalwareDetection.py -p normal_traffic_and_port_scan.pcapng -t 200 -v

Analyzing normal_traffic_and_port_scan.pcapng ...
This tool analyzes normal_traffic_and_port_scan.pcapng using 200 seconds intervals

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
| Type of attack:    1 IP -> N IPs
|      Problem:      probable source host infection
|    Description:    192.168.1.7 is contacting 47 different hosts
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                    

+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
| Type of attack:    1 IP, 1 PORT -> 1 IP, N PORTS
|       Problem:     probable port scanning on 192.168.1.1
|     Description:   192.168.1.7::42919 is contacting host 192.168.1.1 on 3226 different ports
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                    

Analysis terminated 
Closing normal_traffic_and_port_scan.pcapng
```
