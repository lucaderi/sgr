#!/bin/bash

#This script execute 2 docker container Graphite(port 2003,port 100), and Grafana (port 3000), and create 2 volumes of storage for them,
#and execute the collector.

echo "Starting all components (Collector,Grafana,Graphite)..."

#check to see if exist volumes storage for graphite & grafana,otherwise create it
checkGrafanaStorage=$(docker volume ls | grep grafana-storage)

if [ -z "$checkGrafanaStorage" ];
then
	echo "grafana volume not found,it will be created"
	
	docker volume create grafana-storage
	
	if [ $? -ne 0]; then
		echo "Error creating grafana volume"
		exit 1
	fi
else
	echo "grafana volume found.."	
fi

checkGraphiteStorage=$(docker volume ls | grep graphite-storage)

if [ -z "$checkGraphiteStorage" ];
then
	echo "graphite volume not found,it will be created"
	
	docker volume create grafana-storage
	
	if [ $? -ne 0]; then
		echo "Error creating graphite volume"
		exit 1
	fi
else
	echo "graphite volume found.."	
fi


#start grafana container
#if grafana is not install,it will install it
#mount a docker volume in the host system,for save config,dashboard,logs ecc..
echo "Starting Grafana on port 3000...if it not installed,it will be installed"
sleep 1
docker run -d --rm --name=grafana --net=host -v grafana-storage:/var/lib/grafana -p 3000:3000 grafana/grafana

if [ $? -ne 0 ];then
	echo "Error while starting grafana.."
	exit 1
fi

#start graphite container,same thing above
echo "Starting Graphite on ports: 100(Web UI), 2003(Carbon)...if it not installed,it will be installed"
sleep 1
docker run -d --rm --name=graphite -v graphite-storage:/opt/graphite/storage -p 100:80 -p 2003:2003 hopsoft/graphite-statsd

if [ $? -ne 0 ];then
	echo "Error while starting graphite.."
	exit 1
fi

#time to start completely the containers above
sleep 6

#Start collector
echo "Starting Collector..."
java -jar collector.jar 1>/dev/null &

if [ $? -ne 0 ];then
	echo "Error while starting collector.."
	exit 1
fi

echo -e "\n\nSystem started correctly: to shutdown the system run the following command: 1)kill -9 $! 2) docker kill grafana graphite"
