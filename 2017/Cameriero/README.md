# SNMPScan

SNMPScan is a simple network scanner that looks for SNMP agents.
Given a subnet, it sends an SNMP Get request to each host with the default community `public`,
and if the host sends a response back, it is counted as active.

```
Usage: ./snmpscan [-hd] [-c community] [-r retries] [-t timeout] [-p parallel_requests] subnet
```

Options:
- `-h`: Shows the usage.
- `-d`: Enables debug log. Use `-dd` for more verbose output.
- `-c`: SNMP community to use for requests. Default: `public`.
- `-r`: Number of retransmissions. Default: `1`.
- `-t`: Timeout (in ms) to wait for each request. Default: `400ms`.
- `-p parallel_requests`: Limits the maximum number of concurrent requests. Default: `4`.
- `subnet`: Subnet to scan. To scan a single host use `a.b.c.d/32`.


## Compilation

SNMPScan depends on net-snmp. To install development headers on Debian, install the package `libsnmp-dev`:

```
sudo apt install libsnmp-dev
```

To compile SNMPScan:

```
make
```

As an example of the usage of SNMPScan, there is a simple script `test.sh` that spins up some Docker containers with snmpd (see [tnwinc/snmp](https://hub.docker.com/r/tnwinc/snmp/)) and tries a scan.