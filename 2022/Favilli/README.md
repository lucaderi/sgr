# Pcaphunt
Python program to analyze and discover possible threats in a pcap file.
# Supported threats
- **Network Attacks**:
  - arp spoofing
  - ping of death
  - icmp flood
  - tcp syn flood
  - dns request flood
  - unexpected packets loss
  - vlan hopping
- **Host Scanning**:
  - arp scan
  - ip protocol scan
  - icmp ping scan
  - tcp ping syn scan
  - tcp ping ack scan
  - udp ping scan
# How to run
In order to run this program you must have python 3.x and pip3 installed.

The prerequisites to run this program are wireshark, tshark and the python modules nest_asyncio, pyshark and scapy:

- `sudo apt update`
- `sudo apt upgrade -y`
- `sudo apt install wireshark`
- `sudo apt install tshark`
- `pip3 install -r requirements.txt`

Clone the repositoty:
- `git clone https://github.com/markfvl/Pcaphunt.git`

To run the program:
- `python3 pcaphunt.py <filepcap>`

You can also run:
- `python3 pcaphunt.py -s <filepcap>`

to run the supported scapy function instead of the pyshark's one.
  
**Note**: pcaps with annotations or comments could break the application.
