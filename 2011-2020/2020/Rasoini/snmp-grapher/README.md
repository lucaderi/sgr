## Overview

**snmp_grapher** is a Python tool that automatically creates RRDs with rrdtool and updates them with values queried from an SNMP agent of your choice, it also renders  a simple HTML page where you can watch your RRD graphs (they update in real-time too!)

## Installation

**snmp_grapher** requires you to have a working Python 3 interpreter and the [pip](https://pypi.org/project/pip/ "pip") package manager, you also need a working [net-snmp](http://www.net-snmp.org/ "net-snmp") installation and the [rrdtool](https://oss.oetiker.ch/rrdtool/ "rrdtool") software package.

To install all the dependencies on Ubuntu (assuming you already have a working net-snmp installation)
```bash
sudo apt install python3 python3-pip libsnmp-dev librrd-dev rrdtool
pip3 install jinja2 easysnmp rrdtool pyyaml
```
## Usage

```bash
usage: python3 main.py [-h] [-v] [-f] configname

optional arguments:
  -h, --help  show this help message and exit
  -v          Enable verbose mode
  -f          Force replacement of existing RRDs
```

`configname` is the name (with the .yaml extension omitted) of a YAML file inside the `hostsconfig` folder, such config file tells **snmp_grapher** what RRDs to create, with what values they should be updated, and what graphs should be rendered.

`example.yaml` is an example config file, it creates two RRDs measuring the inbound and outbound bytes (measured in megabits) from the network interface with interface index 2 and renders 3 graphs, one showing outbound bytes only, one showing inbound bytes and only, and the last one showing both the inbounds and outbounds measurements. 

You can check these graphs by running `python3 main.py example` and opening the automatically generated `example.html` file in your browser.
