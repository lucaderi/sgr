# tlsCertificateInspector

Simple **TLS certificate** inspector that log the certificates that are:
* **Invalid**: Before or After the certificate validity time
* **Self-Signed**: The Issuer is the same as the Subject

## Description

### TLS
TLS protocol operate above the transport level and it allows a safe communication from src to dst (end-to-end) on TCP/IP network providing a private, authenticated and reliable connection.

### Self-Signed certificate
With self signed certificate we identify certificate that is signed by the same entity whose identity it certifies.
The field that we want to analyze are:
* **Issuer**: The entity who provide the verification
* **Subject**: The entity verified by the certificate 

### Invalid certificate
Each TLS certificate has a temporal validity specified in the validity fields:
* **Not Before**: The certificate is not valid before this datetime
* **Not After**: The certificate is not valid before this datetime

## Prerequisites

To use this software you need:
* Python 3
* [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) that lets you capture or read packets
* [PyShark](https://github.com/KimiNewt/pyshark) which is a python tshark wrapper

## Usage
_**Root privileges are required based on your tshark configuration.**_

``` 
[sudo] python3 main.py [-h] [-i INTERFACE] [-l] [-t TIMEOUT] [-mp MAX_PACKET] [-fi INPUT_FILE] [-fo OUTPUT_FILE] [-v]
               
``` 

### Arguments:
Flag | Store | Description
------------ | ------------- | -------------
 -h, --help | |  show this help message and exit
 -i | INTERFACE | Interface from which to capture (Default eth0)
 -l | | Enables live capture
 -t | TIMEOUT | Specify live sniff timeout in seconds (Default 0 means unlimited)
 -mp | MAX_PACKET | Maximum packet i want to read (Default 0 means unlimited)
 -fi | INPUT_FILE | File that i want to read
 -fo | OUTPUT_FILE | Log file where to store the results
 -v | | Enable verbose mode
 
 ### Output Format
 
 #### Normal
  ``` 
  {IP.SRC}:{SRC.PORT} {TYPE} Certificate (Chain position {POS}/{CHAIN LEN})
  
  Total analyzed certs: {count}, Valid certs: {count}, Self-Signed certs: {count}, Invalid certs: {count}, Both Invalid and Self-Signed certs: {count} 
  ```            
 #### Verbose
  ``` 
 {IP.SRC}:{SRC.PORT} {TYPE} Certificate (Chain position {POS}/{CHAIN LEN}):
        Issuer: DN of the issuer
        Subject: DN of the subject
        Not Before: datetime
        Not After: datetime
        
 Total analyzed certs: {count}, Valid certs: {countn}, Self-Signed certs: {count}, Invalid certs: {count}, Both Invalid and Self-Signed certs: {count} 
  ```            
  **{TYPE}** describes the validity of the certificate and can be:
 * Valid
 * Invalid
 * Self-Signed
 * Invalid and Self-Signed          
 ## Example
 
 ### Capturing from live interface
 #### Command
 ``` 
 sudo python3 main.py -l -i enp0s31f6
``` 
#### Output
``` 
Listening on: enp0s31f6
 131.114.186.12:443 Valid Certificate (Chain position 1/3)
 131.114.186.12:443 Valid Certificate (Chain position 2/3)
 131.114.186.12:443 Self-Signed Certificate (Chain position 3/3)

Total analyzed certs: 3, Valid certs: 2, Self-Signed certs: 1, Invalid certs: 0, Both Invalid and Self-Signed certs: 0
``` 

 ### Reading from file with verbose
 #### Command
 ``` 
 sudo python3 main.py -fi test.pcap -v
``` 
#### Output
``` 
 46.33.70.136:443 Not Valid Certificate (Chain position 1/3):
 	Issuer: ['RelativeDistinguishedName item (id-at-countryName=NL)', 'RelativeDistinguishedName item (id-at-localityName=Amsterdam)', 'RelativeDistinguishedName item (id-at-organizationName=Verizon Enterprise Solutions)', 'RelativeDistinguishedName item (id-at-organizationalUnitName=Cybertrust)', 'RelativeDistinguishedName item (id-at-commonName=Verizon Akamai SureServer CA G14-SHA1)']
	Subject: ['RelativeDistinguishedName item (id-at-countryName=US)', 'RelativeDistinguishedName item (id-at-stateOrProvinceName=MA)', 'RelativeDistinguishedName item (id-at-localityName=Cambridge)', 'RelativeDistinguishedName item (id-at-organizationName=Akamai Technologies Inc.)', 'RelativeDistinguishedName item (id-at-commonName=a248.e.akamai.net)']
	Not Before: 2015-06-19 16:52:07
	Not After: 2016-06-19 16:52:05
 46.33.70.136:443 Valid Certificate (Chain position 2/3)
 46.33.70.136:443 Not Valid Certificate (Chain position 3/3):
 	Issuer: ['RelativeDistinguishedName item (id-at-countryName=US)', 'RelativeDistinguishedName item (id-at-organizationName=GTE Corporation)', 'RelativeDistinguishedName item (id-at-organizationalUnitName=GTE CyberTrust Solutions, Inc.)', 'RelativeDistinguishedName item (id-at-commonName=GTE CyberTrust Global Root)']
	Subject: ['RelativeDistinguishedName item (id-at-countryName=IE)', 'RelativeDistinguishedName item (id-at-organizationName=Baltimore)', 'RelativeDistinguishedName item (id-at-organizationalUnitName=CyberTrust)', 'RelativeDistinguishedName item (id-at-commonName=Baltimore CyberTrust Root)']
	Not Before: 2012-04-18 16:36:18
	Not After: 2018-08-13 16:35:17

Total analyzed certs: 3, Valid certs: 1, Self-Signed certs: 0, Invalid certs: 2, Both Invalid and Self-Signed certs: 0
``` 

