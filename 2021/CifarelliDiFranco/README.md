# DNSLA
A short and simple software to analyze incorrect DNS responses developed by Marco Cifarelli and Leonardo Di Franco.

## Preview
This software mainly makes use of Tshark's ring buffer capture, pyshark's (which also is Tshark but is its python wrapper) file capture and TICK stack (Telegraf, Influx, Chronograf and Kapacitor) without Telegraf. Chronograf is the general manager of the stack and can be used after its activaton at localhost on port 8888: from now on connecting Kapacitor and Influx to Chronograf will be guided by the web page. Every part of the stack can be found easily at https://docs.influxdata.com/platform/install-and-deploy/install/oss-install/.

## Software operation
As soon as the software starts, Tshark is run as a subprocess (making use of python.subprocess.Popen so that the main process doesn't have to wait its termination), with a ring buffer (Tshark's ring buffer functioning can be found at https://www.wireshark.org/docs/man-pages/tshark.html) and its pid is taken and saved for later purposes. It will continuously capture incoming traffic related to the subnet identified by the IP that's over the specified network interface and will put a .pcap file into the _livecap_ directory every 10 seconds.
After Tshark's start, the main function will start checking _livecap_ directory's length until it is at least equal to 2 at which time it can start to extract a file in a lexicographical order every 10 seconds, analyze it with a pyshark file capture and transfer DNS relevant informations reported in the .pcap into a data structure which will be written in the influx database immediately after.  
The data structure has this format:  
| IPv4 | wrong dns reponses |
| :--: | :----------------: |
| 10.0.2.15 | 5 |
| 10.0.2.4 | 7 |

The main function also creates a shutdown_thread which will simply wait for user input until it will be equal to "quit". At that moment, it will send a INT signal to Tshark's process (he has the pid, as said before) which will stop sniffing. The main will now finish analyzing any remaning .pcap files and will terminate.

## Stats and threshold
The threshold consists of mean + stddev on the last _n_ values of every IP address of the network and it's calculated anytime a new .pcap is analyzed that's to say when new values are inserted in the data structure.  
When values are written into influx, if they exceed the threshold Kapacitor will trigger an alarm highlighting which is the faulty IP address and how many DNS wrong responses it made alongside with the threshold. Otherwise nothing will happens.

## Command line options
There are only 2 required flags: __sample__ (-s) that indicates which is the value of _n_ and __interface__ (-i) which is the network interface to capture on.  
There are also report (-r) which if specified will produce a final .pcap containing every sniffed packet during the session, ignore (-ign) which allow to ignore the traffic directed to the sniffing machine (to gain speed and mantain performance), postanalysis (-pa) which need also -r to be used and will produce a .txt analysis of the report and forge (-f) which will forge wrong packets for test purposes (its use is highly discouraged due to performance loss when the sniffing machine also creates/receive too many DNS requests).

## Notes and benchmark
After a several number of benchmarks with a Linux Mint Xfce 20.2 virtual machine and a virtual network, it emerged that:
- The best hardware configuration to allow the software to run efficiently is 4 VirtualBox logical cores (equiv. to 2 cores) and 2048-4096 MB RAM.
- It's better to not overload DNSLA's host with DNS queries in order to gain speed (it's recommended to use the software on a host which is known to not cause "DNS problems" so that it isn't needed to analyze it too).  
This advice is given due to the overhead that NICs can encounter during the sniffing process (receiving and duplicating packets) over high-speed networks.

If the 1st requirement can't be satisfied, try at least to not do DNS requests on DNSLA's host at all.
If instead, the 1st is satisfied, even if the 2nd isn't, it shouldn't slow much the whole process (but still don't exagerate with DNS queries if the hardware isn't very powerful).  
Anyway, we highly recommend to NOT run the software on a station that doesn't satisfy the 1st requirement as results and functioning aren't guaranteed.  
If you don't know your subnet address and mask, do "sudo apt install ipcalc" so that the software will be able to compute it automatically.

__PLEASE NOTE__: this software exploits packet sniffing. It's strictly forbidden to sniff a network without permissions due to GDPR rules.  
Any responsibility on the use of this software is rejected and will be on the user's own since the moment it's downloaded.

## Execution
To test the software you'll need to install Kapacitor, Chronograf and Influx. After that you need to configure Chronograf and Kapacitor with its alarms:
- Create an Influx user (remember username and password).
- Go to http://localhost:8888 and connect your Influx database. The connection URL should be already present but if it's not use http://localhost:8086. Then insert Influx's username and password.
- Choose a dashboard (you can skip this part or choose a random one, it's not important).
- Connect your Kapacitor instance. Kapacitor's URL should be already present but if it's not use http://localhost:9092. Then insert username and password (you can use Influx's ones).
- You should now be on Chronograf's main page. Go to Alerting (exclamation point icon) and choose "build alert rule".
  - In Alert Type choose "threshold", in Time Series choose "progettogr.autogen", "IPv4", mark the "group by" icon and then choose "alert".
  - In Conditions set "equal to" and digit 1 on the right textbox.
  - In Alert Handlers choose "telegram" and insert your bot's chat-ID (to create a bot follow this documentation https://docs.influxdata.com/kapacitor/v1.6/guides/event-handler-setup/#telegram-setup).
  - In Message insert your personal message. 
- DNSLA should now be able to write on Influx that is connected to Chronograf and Kapacitor.  

Before starting the software itself remember to give capabilities to your binaries.  
On our testing machine this capability was enough to run the software: ```sudo setcap cap_net_raw=eip /usr/bin/python3```.  
The software can now be executed by opening a shell (it was used on a bash), changing the cwd to _src_ and typing:  
```python3 dla.py -i <string:network_interface> -s <int:sample>```.  
We also recommend to use -ign option to get a faster .pcap analysis.
