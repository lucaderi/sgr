# CLIENT

These components allow you to expose metrics.
To install the components you need to execute [download.sh](download.sh) and choose what you need.

If you want to see container's metrics, make sure you already have [docker](https://docs.docker.com/get-docker/) installed on your device. The script will install an image with *cAdvisor* pre-installed.
Otherwise, if you choose single pc's metrics, the script will install *Prometheus* and *Prometheus-node-exporter* service.

You can always choose to install both of them.

## cAdvisor

cAdvisor is the tool that exposse the metrics on the 8080 port by default.
To start cAdvisor service you need to active docker's daemons, and to do as follows:
- open a terminal in the Docker folder;
- execute the command ```make up_cAdvisor```;
- if the whole procedure ends without errors you can see cAdvisor service on http://localhost:8080;
- to end the execution of cAdvisor service execute ```make down_cAdvisor```;

For more details on cAdvisor:
- [Docker/Makefile](Docker/Makefile)
- [cAdvisor](https://github.com/google/cadvisor)

## Node-Exporter

Node Exporter is a plugin on Prometheus that allows you to expose metrics from a single linux pc on the 9100 port by default.
To start Node Exporter service do as follows:
- open a terminal in the NodeExporter folder;
- execute ```make up_node_exporter```;
- if the whole procedure ends without errors you can see Node Exporter service on http://localhost:9100;
- to end execution of Node Exporter service execute ```make down_node_exporter```;

For more details on Node Exporter:
- [Makefile](NodeExporter/Makefile)
- [Node Exporter](https://github.com/prometheus/node_exporter)

## Prometheus

Prometheus allows you to scrape the metrics exposed by cAdvisor or Node Exporter. The system provides a default configuration file that is ready to go.
Make sure to overwrite the configuration file located by /etc/Prometheus/prometheus.yml with this [file](prometheus.yml).
If you can't find prometheus following the above path, make sure to read the [prometheus documentation](https://prometheus.io/docs/introduction/overview/).
You can run Prometheus with ```sudo systemctl start prometheus``` and stop it with ```sudo systemctl stop prometheus```.

### Prometheus Configuration
The correct functioning of the architecture is based on the syncronization between Grafana's query and the Prometheus configuration.
The job_name inside the configuration are:
- node -> for single linux pc
- cluster -> for a docker cluster of container

**Warning**:
If you choose to change these names inside the /etc/prometheus/prometheus.yml file, make sure to change the queries accordingly.
Once you have changed the prometheus.yml make sure to restart the service.
