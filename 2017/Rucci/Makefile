.PHONY: deps kairosdb snap grafana ntopng install \
	start start_snap start_grafana start_ntopng start_kairosdb \
	stop stop_snap stop_grafana stop_ntopng stop_kairosdb \
	enable swagger

deps:
	@echo "Installazione di Java..."
	sudo apt-get install -y software-properties-common
	sudo add-apt-repository -y ppa:webupd8team/java
	sudo apt-get update
	sudo apt-get install -y oracle-java8-installer
	echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle" >> .bashrc
	echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle" >> .bash_profile
	-. ~/.bashrc
	@echo "Installazione di Swagger..."
	echo "deb https://dl.bintray.com/go-swagger/goswagger-debian ubuntu main" | sudo tee -a /etc/apt/sources.list
	sudo apt-get update
	sudo apt-get install swagger
	@echo "Controllo curl..."
	-sudo apt-get install -y curl

swagger:
	@echo "Installazione di Swagger..."
	echo "deb https://dl.bintray.com/go-swagger/goswagger-debian ubuntu mai$
	sudo apt-get update
	sudo apt-get install -y swagger

kairosdb:
	cd
	wget https://github.com/kairosdb/kairosdb/releases/download/v1.1.3/kairosdb-1.1.3-1.tar.gz
	tar -xvf kairosdb-1.1.3-1.tar.gz

snap:
	@echo "Installazione di Snap Telemetry..."
	curl -s https://packagecloud.io/install/repositories/intelsdi-x/snap/script.deb.sh | sudo bash
	sudo apt-get install -y snap-telemetry
	-sudo mkdir -p /opt/snap/plugins
	-sudo mkdir -p /opt/snap/tasks
	-sudo mv plugins/snap-plugin-* /opt/snap/plugins
	-sudo chmod +x /opt/snap/plugins/snap-plugin-*
	-sudo mv task.json /opt/snap/tasks
	-sudo chmod +x /opt/snap/tasks/task.json
	-sudo mkdir -p /var/log/snap

ntopng:
	sudo apt-get install libtool-bin build-essential git bison flex libglib2.0 libxml2-dev libpcap-dev libtool libtool-bin rrdtool librrd-dev autoconf automake autogen redis-server wget libsqlite3-dev libhiredis-dev libgeoip-dev libcurl4-openssl-dev libpango1.0-dev libcairo2-dev libnetfilter-queue-dev libmysqlclient-dev zlib1g-dev libssl-dev
	git clone https://github.com/ntop/ntopng.git
	git clone https://github.com/ntop/nDPI.git && cd nDPI && ./autogen.sh && make && cd ..
	cd ntopng && ./autogen.sh && ./configure && make && make install && cd ..

grafana:
	@echo "Installazione di Grafana..."
	wget https://s3-us-west-2.amazonaws.com/grafana-releases/master/grafana_4.4.0-8311pre1_amd64.deb
	sudo dpkg -i grafana_4.4.0-8311pre1_amd64.deb

install:
	@make deps
	@make kairosdb
	@make snap
	@make ntopng
	@make grafana

start_grafana:
	sudo systemctl start grafana-server

start_snap:
	sudo systemctl start snap-telemetry

start_kairosdb:
	sudo kairosdb/bin/kairosdb.sh start
	cd ..

start_ntopng:
	sudo ntopng -w 80 &

start:
	@make start_kairosdb
	@make start_ntopng
	@make start_snap
	@make start_grafana

stop_grafana:
	sudo systemctl stop grafana-server

stop_snap:
	sudo systemctl stop snap-telemetry

stop_ntopng:
	sudo kill -INT $(pidof ntopng)

stop_kairosdb:
	sudo kairosdb/bin/kairosdb.sh stop

stop:
	@make stop_grafana
	@make stop_snap
	@make stop_ntopng
	@make stop_kairosdb

enable:
	sudo systemctl daemon-reload
	sudo systemctl enable grafana-server
	sudo systemctl enable snap-telemetry
