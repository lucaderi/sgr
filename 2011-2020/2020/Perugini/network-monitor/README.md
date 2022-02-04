# net-monitor

A GoLang script that send network usage traffic to influx stack

## Requirements

`docker` and `influxDB 2.0`

##### Running on Docker

> ```$ docker run --name influxdb -p 9999:9999 quay.io/influxdb/influxdb:2.0.0-beta```

To use `influx` cli, console into the `influxdb` Docker container:

```$ docker exec -it influxdb /bin/bash```

For more information visit: <https://v2.docs.influxdata.com/v2.0/get-started/>

##### Running on Mac OS X

> ```
> $ https://dl.influxdata.com/influxdb/releases/influxdb_2.0.0-beta.8_darwin_amd64.tar.gz
> $ tar zxvf influxdb_2.0.0-beta.8_darwin_amd64.tar.gz
> ```

##### Running on Linux Binaries (64-bit)

> ```
> $ wget https://dl.influxdata.com/influxdb/releases/influxdb_2.0.0-beta.8_linux_amd64.tar.gz
> $ tar xvfz influxdb_2.0.0-beta.8_linux_amd64.tar.gz
> ```

##### Running on Linux Binaries (ARM)

> ```
> $ wget https://dl.influxdata.com/influxdb/releases/influxdb_2.0.0-beta.8_linux_arm64.tar.gz
> $ tar xvfz influxdb_2.0.0-beta.8_linux_arm64.tar.gz
> ```

## Binaries

You can find `net-monitor` binaries on the release tag

## Compile

```
$ go build net-monitor.go
```
## How to use

```net-monitor -bucket [my-influxdb-bucket] -org [my-influxdb-organization] -token [influxdb-auth-token]```

Default values:
 - host: `localhost`
 - community: `public`
 - snmpPort: `161`
 - influxUrl: `http://localhost`
 - influxPort: `9999`
 - interval: `2s`

## Options

Type `$ net-monitor -help`

```
Usage: sys-status [options]
  -bucket string
        bucket string for telegraf
  -community string
        community string for snmp (default "public")
  -host string
        hostnameSnmp or ip address (default "localhost")
  -influxPort uint
        influxPort number (default 9999)
  -influxUrl string
        influx url (default "http://localhost")
  -interval string
        interval in seconds before send another snmp request (default "2s")
  -org string
        organization string for telegraf
  -snmpPort uint
        snmp port number (default 161)
  -token string
        auth token for influxdb
  -version
        output version
```

## Dependencies

[gosnmp](https://github.com/soniah/gosnmp) used for snmp requests
```
go get github.com/soniah/gosnmp
```# network-monitor
