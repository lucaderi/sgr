# Traffic-flow

The purpose of this tool is capture the various flows reached by the network-board. \
It divides the flows in input and output, then they are catalogated by protocol packet (TCP or UDP)
and finally they are assigned to the relative process that is listening on the port and ip address 
that are situated in the packet header.

In this project were used *Scapy* https://guedou.github.io/talks/2019_BHUSA/Scapy.slides.html#/ \
Scapy is a packet manipulation tool for computer networks, but it is used also for scanning, tracerouting, 
probing, unit tests, attacks, and network discovery.

For the use you need to run:
```
make install
```
this install all the python module that you need, \
then: 
```
make test
```
or simply 
```
make
```
