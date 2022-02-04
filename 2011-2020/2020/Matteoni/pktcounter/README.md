### pktcounter.py
##### Installation
Install `python3`, `python3-pip`, `pyshark`, `rrdtool` and `influxdb`
```
sudo apt install python3 python3-pip rrdtool librrd8 librrd-dev influxdb influxdb-client influxdb-dev
pip3 install pyshark
pip3 install rrdtool
pip3 install influxdb
```
##### Usage
Usage: `python3 pktcounter.py [--interface <interface>] [--port <InfluxDB server port>]
[--adminname <InfluxDB admin username>] [--adminpwd <InfluxDB admin password>]
[--username <InfluxDB user username>] [--userpwd <InfluxDB user password>]`

#### Example
Example: `python3 pktcounter.py --interface wlp1s0`

To stop the scripts simply press CTR-C. The scripts will build the RRD graph `<interface>packets.rrd.png`
and put it in the current directory (for example: `wlp1s0packets.rrd.png`).

As for InfluxDB, the db will be called `<interface>packetsdb` (for example: `wlp1s0packetsdb`). You can
use Chronograph or the InfluxDB web interface to view the data.
