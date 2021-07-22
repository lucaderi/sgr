# Sflow-Monitoring-Tool

## Introduction

This tool utilizes the sFlow packet sampling technology to determine the Top Talkers in the network.
To decode sFlow data the tool utilizes a Python library called [python-sflow](https://github.com/pvanstam/python-sflow)

---

## Requirements

* [sFlow](https://sflow.net/downloads.php)

---

## Run

In order to start analizing packets it is necessary to configure sFlow by adding a collector in the config file, under the section "collectors".

At this point the only thing left to do to start the tool is executing the following command:

    python3 main.py

The program accepts the following arguments, and if they are not specified the default value is used:
* -p    sFlow collector port (default=6343)
* -a    sFlow collector ip (default=127.0.0.1)
* -m    Max number of talkers to display (default=0, unlimited)
* -h    Help function


It is also possible to interact with the tool by pressing the following keys while it's running:

* r Reload the informations
* s Switch sorting method
* q Exit the tool
