README


Sniffit is a tool that reads packets live or from a pcap file, and using rrdtool for statistics.

Author : Giuseppe Di Francesco 

README.txt : info  


REQUIREMENTS
===============
 libpcap 
 rrdtool


COMPILE
===============
 make clean  
 make Sniffit


USAGE 
===============

 mysniffer [-r] <file rrd> [-l]  -i <interface> -f <file>.pcap 
   -r <file>.rrd    | rrd file \n");
   -l               | live capture\n");
   -f <file>.pcap   | Pcap file for read or write\n");
   -i <interface >  | interface for capture\n");


