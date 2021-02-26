# tls-analyzer
Read from a file pcap, extract flows and give information about host-protocol distribution and tls traffic.

## Requirements:
  >[nfstream](https://github.com/nfstream/nfstream) *: 'a Python framework providing fast, flexible, and expressive data structures designed to make working with online or offline network data both easy and intuitive.'*  
Nfstream flow-based aggregation consists of aggregating packets into flows based on a shared set of characteristics (flow key, e.g., source IP address, destination IP address, transport protocol, source port, destination port, VLAN identifier).
  
## Installing requirements:  
  Use your current version of pip to install nfstream
  > pip3 install nfstream
  
## Description:
  Print, for each host detected in the pcap file:  
    The amout of traffic that host generated;  
    The portion of traffic for each application layer protocol supported;  
    Tls statistics.
### tls statistics:  
  Prints each TLS flow sorted by the amount of traffic.  
  For each flow , it detects what kind of traffic is over the TLS protocol (e.g TLS.stackoverflow, TLS.tesla, TLS.chess ) by checking if the requested server name is inside top10k.txt (top10k most visited sites), and validates SNIs for existence by resolving the hostname.

## Usage:  
  This is a command line tool, it takes only one parameter and has to be a .pcap file.  
  
  You can generate a pcap file by using a networking tool like Wireshark (graphical), or by command line with tcpdump.  
  To capture a session with tcpdump:  
  Identify your network interface by typing in the terminal ifconfig (Linux) or ipconfig (Windows);  
  Once you know what network interface you are using, let's say its name is 'wlan0' :  
  > * start capture:  tcpdump -i wlan0 -w pcap_files/traffic.pcap
  > * end capture: CTLR-C  
  
  Note that tcpdump requires sudo privileges to run, so you may run it as super user.

  When you got the pcap file you can run the program:
  > python3 tls_printer.py pcap_files/traffic.pcap
  
  To save the output for further read: 
  > python3 tls_printer.py pcap_files/traffic.pcap >> report.txt  
  
  TODO: add a better format to save the output file (e.g csv )
  
## Examples:  
  ![](img/1.png)
