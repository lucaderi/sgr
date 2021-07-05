# Grafana dashboard for ntopng

The dashboard allows you to quickly visualize the data produced by ntopng, with a particular focus on what kind of traffic is going through, and where it comes from. ntopng score is also used to give an immediate overview of what hosts should be given more attention.

## Software used

The dashboard needs a working setup consisting of a running instance of ntopng configured to send data to InfluxDB v1.x, and a running instance of grafana configured to query data from InfluxDB v1.x. Please note that a valid Enterprise ntopng license is needed to correctly visualize all kind of data.

## Installation

ntopng can be installled by downloading a pre-built package from [here](https://packages.ntop.org) or by compiling it from [source code](https://github.com/ntop/ntopng). After having ntopng installed, please make sure that it's running with the command:
```bash
systemctl status ntopng.service
```
If it's not, start ntopng by doing:
```bash
systemctl start ntopng.service
```
Once ntopng is installed, proceed with the installation of InfluxDB v1.x available [here](https://portal.influxdata.com/downloads/). If you are using Ubuntu or Debian, you can install InfluxDB v1.8.6 by doing:
```bash
wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.6_amd64.deb
dpkg -i influxdb_1.8.6_amd64.deb
```
Please make sure that InfluxDB is correctly installed by executing the following command in the shell. If an interactive session appears, InfluxDB has been correctly installed.
```bash
influx
```
The fist line of the interactive shell should look like:
```bash
Connected to http://localhost:8086 version 1.8.6
```
Please note down the local URL of InfluxDB because you will need to insert it into ntopng and Grafana settings.
We will also use the InfluxDB interactive shell to create a database that ntopng will use to store data, and Grafana will query to produce graphs.
To create the database type the following command in the interactive shell:
```bash
CREATE DATABASE ntopng
```
To verify that the database has been correctly created, type the following command and verify that 'ntopng' is present in the list.
```bash
SHOW DATABASES
```
If the database has been correctly setted up, go to the ntopng GUI (defaults to localhost:3000), then Settings -> Timeseries. In the Timeseries Database section, switch from RRD to InfluxDB 1.x if not already selected, and put the InfluxDB URL that we noted down before in the respective field; then type 'ntopng' in the InfluxDB Database field.
To make the most out of the dashboard, switch the Host Timeseries to Full in the Local Hosts Timeseries section, and turn on the Countries field in the Other Timeseries section. Click on the save button at the bottom of the page, and a green message should appear indicating the correct setup of ntopng -> InfluxDB. 
Since Grafana also has 3000 as the default port, it's advisable to change it by editing /etc/grafana/grafana.ini and changing the http_port to something else (e.g 3500). Now restart the service by doing:
```bash
systemctl restart grafana-server.service
```
Log into grafana GUI by going to localhost:3500. To setup InfluxDB -> Grafana, go to Configuration -> Data Sources -> Add data source. Choose a name for the configuration, pick InfluxQL as query language, and put the InfluxDB URL that we noted down before in the URL field; type 'ntopng' in the Database field, and hit Save & Test. A green message should appear indicating the correct configuration of InfluxDB -> Grafana.
To import the dashboard go to Create -> Import -> Upload JSON file -> select the dashboard in JSON format and click Import. The dashboard should now be available in Dashboards -> Home -> ntopng - network status.

## Instance example

![1](https://github.com/lucaderi/sgr/blob/master/2021/Coltelli/demo_images/1.png?raw=true "1")
![2](https://github.com/lucaderi/sgr/blob/master/2021/Coltelli/demo_images/2.png?raw=true "2")
![3](https://github.com/lucaderi/sgr/blob/master/2021/Coltelli/demo_images/3.png?raw=true "3")
