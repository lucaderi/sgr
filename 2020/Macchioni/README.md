# http_headers_counter

__http_headers_counter__ uses scapy library for parsing .pcap files, counts every http header encountered and then compares each one with a list of known headers.

## Prerequisite
`sudo apt-get install -y python3-pip`

`pip3 install --pre scapy[basic]`

## Usage
```
usage: http_headers_counter.py [-h] [-f FILES [FILES ...] | -d DIR]

optional arguments:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --files FILES [FILES ...]
                        specify the pcap files
  -d DIR, --dir DIR     specify the pcap directory
```
If no optional arguments are provided, it reads from `./pcaps` default directory

## Example
```
tubuntu@tubuntu-Surface-Pro-3:~/Scrivania/http_headers_counter$ ./http_headers_counter.py 
Looking for pcaps file in '/home/tubuntu/Scrivania/http_headers_counter/pcaps' directory
Reading from 'first_file.pcap'
Reading from 'second_file.pcap'
Reading from 'third_file.pcap'

*******************************************************************
***************************** Summary *****************************
*******************************************************************
HEADER                                  COUNTS              KNOWN
Connection                                31                 yes
Host                                      17                 yes
User-Agent                                17                 yes
Accept                                    17                 yes
Date                                      17                 yes
Content-Type                              17                 yes
Server                                    15                 yes
Content-Length                            13                 yes
Cache-Control                             11                 yes
Last-Modified                             10                 yes
content-transfer-encoding                  8                  no
Expires                                    8                 yes
Upgrade-Insecure-Requests                  5                 yes
Accept-Encoding                            5                 yes
Accept-Language                            5                 yes
Transfer-Encoding                          3                 yes
Location                                   3                 yes
Accept-Ranges                              3                 yes
Age                                        3                 yes
Etag                                       3                  no
X-Cache                                    3                  no
Content-Disposition                        2                 yes
If-Modified-Since                          2                 yes
If-None-Match                              2                 yes
X-CCC                                      2                  no
X-CID                                      2                  no
Set-Cookie                                 1                 yes
Vary                                       1                 yes
CF-Cache-Status                            1                  no
CF-RAY                                     1                  no
cf-request-id                              1                  no
Keep-Alive                                 1                 yes
Warning                                    1                 yes
X-Powered-By                               1                 yes
ETag                                       1                 yes
Pragma                                     1                 yes
server                                     1                  no
X-Content-Type-Options                     1                 yes
X-ServerName                               1                  no

Total HTTP packets analized: 34
Total HTTP headers found: 39 (29 knowns | 10 unknowns)

```

## Tested systems
- Ubuntu 20.04 64bit
- Windows 10 64bit

# Use of this tool

Some malware communicate with their Command-and-Control server to send and receive information or commands to execute by using HTTP protocol.

This tool allowed me to detect unknown headers in some of malware pcap files ([http://malware-traffic-analysis.net](http://malware-traffic-analysis.net)) and add a [new feature](https://github.com/ntop/nDPI/commit/db5cd92fe11d132a679c1970fb4f2d9a71a95390#diff-27c94f3231eaeb6e7d43085c1b4a87b3) in [nDPI](https://github.com/ntop/nDPI) library: compare my detected headers with every nDPI inspected header.
