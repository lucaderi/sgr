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

## Debugging

In order to understand better how nDPI works, I had to set up my IDE: *Visual Studio Code*. In particular, *C/C++ extension* allowed me to configure the debugger: 

-  From the main menu, choose **Run > Add Configuration...** and then choose **C++ (GDB/LLDB)**

- You'll see a dropdown to choose the debugging configuration. Choose **gcc**.

- Visual Studio Code creates a `launch.json` file, opens it in the editor:

  ```json
  {
      "version": "0.2.0",
      "configurations": [
          {
              "name": "(gdb) Launch",
              "type": "cppdbg",
              "request": "launch",
              "program": "${workspaceFolder}/example/ndpiReader",
              "args": ["-i ../pcap_files/my_pcap.pcap"],
              "stopAtEntry": false,
              "cwd": "${workspaceFolder}",
              "environment": [],
              "externalConsole": false,
              "MIMode": "gdb",
              "setupCommands": [
                  {
                      "description": "Abilita la riformattazione per gdb",
                      "text": "-enable-pretty-printing",
                      "ignoreFailures": true
                  }
              ]
          }
      ]
  }
  ```

  In particular:

  - ` "program": "${workspaceFolder}/example/ndpiReader"`  in order to start the nDPI example main program `ndpiReader`.
  - `"args": ["-i ../pcap_files/my_pcap.pcap"]` in order to read a pcap file and test it.

- Add a breakpoint and click **F5** to start debugging.



## Writing the function

All suspicious headers that were found using `http_headers_counter`, were alphabetically divided for optimazing the research:  

```c
static const char* suspicious_http_header_keys_A[] = { "Arch", NULL};
static const char* suspicious_http_header_keys_C[] = { "Cores", NULL};
static const char* suspicious_http_header_keys_M[] = { "Mem", NULL};
static const char* suspicious_http_header_keys_O[] = { "Os", "Osname", "Osversion", NULL};
static const char* suspicious_http_header_keys_R[] = { "Root", NULL};
static const char* suspicious_http_header_keys_S[] = { "S", NULL};
static const char* suspicious_http_header_keys_T[] = { "TLS_version", NULL};
static const char* suspicious_http_header_keys_U[] = { "Uuid", NULL};
static const char* suspicious_http_header_keys_X[] = { "X-Hire-Me", NULL};
```

Every lines of each HTTP packet found by nDPI dissector, has been parsed by looking first at the initial letter. If there's a match then the line could be a suspicious header. In that case, it passed to `is_a_suspicious_header(...)` function (see below).

```c
static void ndpi_check_http_header(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  u_int32_t i;
  struct ndpi_packet_struct *packet = &flow->packet;

  for(i=0; (i < packet->parsed_lines)
	&& (packet->line[i].ptr != NULL)
	&& (packet->line[i].len > 0); i++) {
    switch(packet->line[i].ptr[0]){
    case 'A':
      if(is_a_suspicious_header(suspicious_http_header_keys_A, packet->line[i])) {
	NDPI_SET_BIT(flow->risk, NDPI_HTTP_SUSPICIOUS_HEADER);
	return;
      }
      break;
    case 'C':
      if(is_a_suspicious_header(suspicious_http_header_keys_C, packet->line[i])) {
	NDPI_SET_BIT(flow->risk, NDPI_HTTP_SUSPICIOUS_HEADER);
	return;
      }
      break;
    case 'M':
      if(is_a_suspicious_header(suspicious_http_header_keys_M, packet->line[i])) {
	NDPI_SET_BIT(flow->risk, NDPI_HTTP_SUSPICIOUS_HEADER);
	return;
      }
      break;
    case 'O':
      if(is_a_suspicious_header(suspicious_http_header_keys_O, packet->line[i])) {
	NDPI_SET_BIT(flow->risk, NDPI_HTTP_SUSPICIOUS_HEADER);
	return;
      }
      break;
    [...]
    }
  }
}
```

Every HTTP header ends with a colon character. So, it was easy to extrapolate it, use C pointer arithmetic and compare it with every known suspicious headers.

```c
static int is_a_suspicious_header(const char* suspicious_headers[], struct ndpi_int_one_line_struct packet_line){
  int i;
  unsigned int header_len;
  const u_int8_t* header_limit;

  if((header_limit = memchr(packet_line.ptr, ':', packet_line.len))) {
    header_len = header_limit - packet_line.ptr;
    for(i=0; suspicious_headers[i] != NULL; i++){
      if(!strncasecmp((const char*) packet_line.ptr,
		      suspicious_headers[i], header_len))
	return 1;
    }
  }

  return 0;
}
```

