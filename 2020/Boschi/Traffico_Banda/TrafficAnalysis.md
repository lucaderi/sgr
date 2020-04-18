## Overview of the tool
This tool use SNMP agent to gather some information about network traffic. It can store one month of data.
The tool save the data in a timeline database (.rrd) and use this information to create graphs on demand.
Data are expressed as MegaBit in the "Traffic Network" graph, and as a percentage in the "Bandwidth" graph.



## Requirements

**This tool works with python3 and SNMP**
**SNMP have to be correctly installed and configured on the system**

Install easySNMP library on Debian/Ubuntu systems:

	sudo apt-get install libsnmp-dev snmp-mibs-downloader
	sudo apt-get install gcc python-dev
	pip3 install easysnmp

Install rrdtool on Debian/Ubuntu systems:
	
	sudo apt-get install librrd-dev libpython3-dev
	pip3 install rrdtool


## Configuration

Give view permission to IF-MIB by adding this line (if not present) in /etc/snmp/snmpd.conf under "Access Control" section:

	view   systemonly  included   .1.3.6.1.2.1.2



## Usage
First you need to have all the files in the same folder, and you also need to load MIBS: you can use snmp.conf file, or you can use the command on shell:
	
		export MIBS=all
Now you can start up the tool:
	
		python3 ControlloBanda.py

The tool start to collect data, and when you want you can create graphs with this data. The script that creates graphs have 4 different period of time to use: halfhour, hour, day, week, and an option to insert a custom hour.

		python3 rrd_graph.py


## Output
While the script is collecting data it also show some minimal instant information, but the true output of the tool are of course the graphs.





	
