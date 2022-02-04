# Traffic-flow

The purpose of this tool is capture the various flows reached by the network-board. \
The flows are bidirectional and they are catalogated by protocol packet (TCP or UDP) and the relative 
process that is listening on the port and ip address 
that are situated in the packet header. \

In this project were used *Scapy* https://guedou.github.io/talks/2019_BHUSA/Scapy.slides.html#/ \
Scapy is a packet manipulation tool for computer networks, but it is used also for scanning, tracerouting, 
probing, unit tests, attacks, and network discovery.

For the use you need to install scapy:
```
pip install --pre scapy[basic]
```
then tabular to show the informations about flows 
```
pip3 install tabulate
```
to run the application:
```
sudo python3 Traffic.py
```
sudo is required for scapy to sniff packets
