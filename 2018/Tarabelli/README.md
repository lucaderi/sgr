
# Monitoring the network traffic of a device on the LAN

NetworkMonitoring is a program for capturing and analyzing the network traffic of a device located in a LAN, using arp spoofing techniques.
The program is able to show DNS requests on the shell and statistics, obtained from TCP and UDP packets, on a web interface offered by the Chronograf application.

## Usage

```
Usage: sudo python3 NetworkMonitoring.py [-hv] [-i interface] [-g gateway] [-t target] 
```

After starting the program go to the web page http://localhost:8888 to view the statistics.

Options:

- `-h`: Shows the usage.
- `-i`: interface of capture network traffic.
- `-t`: Target IP of device for analysis.
- `-g`: Gateway IP of router device.
- `-e`: ex: example of usage
- `-v`: Enable verbose mode.

> Ex: sudo python3 sniffer.py -i enp2s0 -t 192.168.1.3 -g 192.168.1.1

## Installation

 Installation guidelines


```
sudo apt install python3-influxdb 
sudo apt install python3-pip 
```

If you prefer to use a virtual environment


```
sudo pip3 install virtualenv 
virtualenv venv
source venv/bin/activate
```

Dependencies installation


```
sudo pip3 install -r requirements.txt
```

Necessary database tools : **Influxdb**, **chronograf**:

visit https://portal.influxdata.com/downloads

Start the services:


```
service influxdb start
service chronograf start
```

Finally, copy the chronograf-v1.db file to /var/lib/chronograf/ to import dashboard settings.

PS: for correct operation make sure that the TCP port of influxdb is 8086
The software was developed for linux only and tested on debian based distro: 
linux mint 18.3 and ubuntu 18.04.
