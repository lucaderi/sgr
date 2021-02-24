# tls-analyzer
Read from a file pcap, extract flows and give information about host-protocol distribution and more detailed information about tls traffic.

## Requirements:
  >[nfstream](https://github.com/nfstream/nfstream) *: 'a Python framework providing fast, flexible, and expressive data structures designed to make working with online or offline network data both easy and intuitive.'*
  
## Description:
  For each host prints:  
    The amout of traffic it generated  
    The amout of traffic generated for each protocol detected  
### tls statystics:  
  It prints each flow line by line in descending order by the amout of traffic.  
  For each flow, it detects what kind of traffic is over the TLS protocol (e.g TLS.stackoverflow , TLS.tesla , TLS.chess ) by checking if the requested server name is inside top10k.txt (top10k most visited sites), and validates SNIs for existance by resolving the hostname.
    
    
  
  
  
