## teamsCheck

INSTALLATION

- You need to install these packages before running the script:
    - sudo apt-get install libsnmp-dev snmp-mibs-downloader gcc python-dev
    - pip3 install easysnmp
    - pip3 install rrdtool

DESCRIPTION:

- It's a simple python script that monitoring the InOctet and OutOctet counters. When it takes the data
reports them on rrd databases and then make the graph. In the graph with the colors blue and green we represent the values 
of the counters when teams is not running, in red and violet the values of the counters when teams is running.
    
USAGE:

- ./teamsCheck.py

PARAMETERS:
    
- community: community string for snmp.
- host: host that receive the requests sent.
- version: version of snmp for the requestes.
    

