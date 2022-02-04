
cpu_mem.sh

  
  

DESCRIPTION:

A basic bash script that use snmpget to send request to an host, where one snmp demon is running.

The script display memory usage and cpu load. The script iterates to display one or more time the information.

The number of iterations must be given in input.


REQUIREMENTS:

You have to ensure read access to some OIDs, so add in your snmpd.conf file these lines:
--> view   systemonly  included   .1.3.6.1.4.1.8072
--> view   systemonly  included   .1.3.6.1.4.1.40310.1
--> view   systemonly  included   .1.3.6.1.4.1.40310.2
  

USAGE:

First, you have to ensure exec permission to the script, using the command:
--> chmod +x cpu_mem.sh
Now you can run the script:
--> ./cpu_mem.sh [community] [host] [numIterations]

  

PARAMETRES:

community: community string for snmp

host: host where you send snmp requests

numIterations: times the script send a request to snmpd and display the informations

  
  

OUTPUT:

************************************************

[MEMORY]

Total --------> 3064584 kB

Free ---------> 497072 kB

Total busy ---> 2567512 kB

Busy (used) --> 1459956 kB

Buff/Cached --> 1107556 kB

[CPU]

Load over last minute 0.15 %

Load over last 5 minute 0.15 %

Load over last 10 minute 0.16 %

***********************************************
