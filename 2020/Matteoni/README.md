### SimpleSNMPStat.py
##### Installation
Install `python3`, `python3-pip` and `pysnmp`
```
sudo apt install python3 python3-pip
pip3 install pysnmp
```

##### Usage
Usage: `python3 simplesnmpstat.py community hostname [port]`

#### Example
Example: `python3 simplesnmpstat.py public demo.snmplabs.com`

Output
```
Requesting demo.snmplabs.com:161

15.40.40

new system name
	Linux zeus 4.8.6.5-smp #2 SMP Sun Nov 13 14:58:11 CDT 2016 i686
	Uptime		26 days, 16:26:58.660000 (230561866)
	CPU		0%
	Mem total	1021976 KB
	Mem avail.	10000 KB

1 (15.40.44)
	CPU		0%
	Mem		10000/1021976 KB

2 (15.40.46)
	CPU		0%
	Mem		10000/1021976 KB

3 (15.40.48)
	CPU		0%
	Mem		10000/1021976 KB

4 (15.40.50)
	CPU		0%
	Mem		10000/1021976 KB

5 (15.40.51)
	CPU		19%
	Mem		10000/1021976 KB
```
