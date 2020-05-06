## memCpuCheck

INSTALLATION

- You need to install these packages before running the script:
    - sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
    - pip3 install easysnmp
    - pip3 install rrdtool


DESCRIPTION:

- It's a simple python script that returns the ticks values of the processors, 
the value of the total memory, the value of the available memory and also checks the in_octets values obtained with snmp.
Reports the data on three rdd databases which are then displayed through graphs.
    
USAGE:

- ./memCpuCheck.py

PARAMETERS:
    
- community: community string for snmp.
- host: host that receive the requests sent.
- version: version of snmp for the requestes.
    
OUTPUT:
	
- CPU usage: ... %
- Free CPU: ... %
- The number of ticks spent idle, for x processors: ...
- Available memory: ... kb
- Total memory: ... kb

GRAPHICS

![CpuGraph](img/cpuGraph.png)
![memGraph](img/memCheckGraph.gif)
![inOctetGraph](img/inOctet.gif)
