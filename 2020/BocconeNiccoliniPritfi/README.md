# Jitter - a simple network monitoring tool        
![GitHub repo size](https://img.shields.io/github/repo-size/Crostatus/Jitter) ![GitHub](https://img.shields.io/github/license/Crostatus/Jitter) ![GitHub top language](https://img.shields.io/github/languages/top/Crostatus/Jitter?color=red)

 ## Introduction   
 **Disclaimer:** *this program is not for professional use. It has been written only for educational purpose, as an assignment project for the Network Management course at [Unipi](https://di.unipi.it/).*

This is a sniffer example using [libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) to analyze the communication frequency of TCP streams.    
libpcap is a portable C/C++ library for network traffic capture. ([GitHub repository](https://github.com/the-tcpdump-group/libpcap))

**What does the jitter measure?** The jitter is defined as the *variation* in the delay (or latency) of received packets.

This program aims to see the jitter of TCP comunications happening from/to the host machine, and detects suspicious jitter variation.
In this text we will try to cover and explain the essential components of this program and how it works in the following order:
 1. **[Aim of this tool](#aim-of-this-tool)**
 2. **[Project structure](#project-structure)**
 3. **[How to build it](#how-to-build-it)**
 4. **[Program usage](#program-usage)**   
 5. **[How it works](#how-it-works)**
 6. **[Testing](#testing)**

 &nbsp;**[Credits](#credits)**

 # Aim of this tool  
 The main purpose of this program is to allow the user to monitor his network traffic.    
 An alarm is sent to the user when a detected connection happens to have a unusual jitter behaviour.    
 Since **an alarm could not represent a malicious activity**, this software can be seen as **a tool to have a first look on what's going on in his network**.    

 It also offers the option to **save, as a graph, the image of a communication** trend about his jitter. Those images will be stored in the *graphs* directory.

 ## Project structure
This is a quite small project, but it's never a bad idea to give a general overview for a better file exploration.     

📁headers    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter_data.h    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃time_tools.h    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃menu.h    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃gnuplot_i.h    

📁src    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter3.c &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *main packet capture loop*   
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter_data.c &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  *data structure to store sniffed packets*    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃time_tools.c  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *implements time related methods (e.g get elapsed time)*    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃menu.c &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *user menu navigation & print methods*    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃gnuplot_i.c&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*used to represent data in graphs*    

📁graphs    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🖼img.png&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*saved communications graph*

🛠️Makefile &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *project builder*  

⚙️jitter &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp; *executable file*  

💻 test.sh &emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp; script file

## How to build it
In order to compile this project, you need to have [libpcap](https://github.com/the-tcpdump-group/libpcap) (*v 1.9.1-3 or newer*), [gnuplot](http://www.gnuplot.info/) (*v 5.2 or newer*) and [libnotify](https://developer.gnome.org/libnotify/0.7/) (*v 0.7.9-1ubuntu2*) installed.    
One way to easily get it, **on Ubuntu**, is to use the following commands:    
`sudo apt-get install libpcap-dev`&nbsp;&nbsp;&nbsp;`sudo apt-get install gnuplot`&nbsp;&nbsp;&nbsp; `sudo apt-get install libnotify-dev`    

**For testing only** &nbsp; [nmap](https://nmap.org/nping/) and [xterm](https://linux.die.net/man/1/xterm) are also needed. To get them:    
`sudo apt install nmap` &nbsp;&nbsp; `sudo apt-get install -y xterm`



To check your current versions:    
`apt-cache show libpcap-dev` &nbsp;&nbsp;&nbsp;	&nbsp;&nbsp;`gnuplot-V`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `apt-cache show libnotify-dev`

That's it! Now you can use the Makefile to get everything done, just run `make` in the project folder and you are ready to go.     

## Program usage
This program, once started, can capture packets *endlessly* or *stop once a default amount has been reached*.
Those two ways to run and which network device to use can be set giving extra parameters at launch. All available parameters are listed below:

|NAME                |TYPE                       |OPTIONAL                         |
|----------------|-------------------------------|-----------------------------|
|packet_number|Non negative integer            |yes         |    
|device_name| String            |yes         |

The network device to use can be chosen by adding its name as an additional parameter, writing "**-i** device_name".  
If no "**-i** *device_name*" is provided, the first network device listed by [libpcap's method `pcap_findalldevs()`](https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html) will be used.

**Otherwise**, if you need help, you can run it with "**-h**" to read a short description on how to launch and what to expect from it.

**Examples**:    
- `sudo ./jitter 50` &emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp;&nbsp; will stop after capturing the next 50 packets.    
- `sudo ./jitter`&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; will start sniffing until interrupted.    
- `sudo ./jitter -i wlp2s0`&emsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; will start sniffing from the wlp2s0 interface until interrupted.
- `sudo ./jitter 50 -i wlp2s0` &nbsp; will stop after capturing the next 50 packets from the wlp2s0 interface.  
- `sudo ./jitter -h` &emsp;&emsp;&emsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; will show a help description.

**In the first four cases** the sniffing can be correctly stopped sending a **SIGINT** (*Ctlr + c*) interruption to this process.

**It is required** to run this program with `sudo`.

Once that the sniffing has stopped, a very simple menu will show up to see the collected data.   

## How it works
This program aims to detect and notify a **suspicious** jitter variation happening in a **TCP** communication that has been captured since the program is sniffing.    
Each pair of <IP_source, IP_destination> gets treated as a different communication, and it will be prepresented as **IP:IP_source->IP_destination**.    

The programs notes every time a pair of hosts exchanges a stream of TCP packets by looking at the ones having `SYN = 1` ( The **SYN** flag synchronizes sequence numbers to initiate a TCP connection ).    
Every time that one of those packets gets captured, informations about it will be stored, as:    
- Arrive time    
- Delay from previous packet
- Source port
- Destination port
- Jitter of its communication
- Order of arrival

In order to calculate the jitter, since it represents the variance of intra-packet delay, **at least three** TCP streams exchanges need to have happened in a communication.  

### How the jitter gets calculated?  
A communication's jitter gets calculated using the following formula:  
<img src="https://latex.codecogs.com/gif.latex?\dpi{200}&space;\bg_white&space;\fn_jvn&space;\LARGE&space;jitter&space;=&space;sum(|x(i)&space;-&space;x(i-1)|)&space;/&space;(n-1))">    

Where:   
&nbsp;&nbsp;&nbsp;*x(i)*&nbsp;&nbsp;= arrive time of the i th packet.    
&nbsp;&nbsp;&nbsp;*n* &nbsp;&nbsp;&nbsp;&nbsp;= total packets number at the moment.

### When is a connection suspicious?    
This program defines a behaviour suspicious when a new jitter undergoes **a variation greater than 50% of the average jitter's communication**.    

A minimal example on a <IP_source, IP_destination> exchange of TCP packets:    

|Packet with `SYN = 1`              |Jitter (ms)                       | Average jitter (ms)| Is suspicious         |           
|----------------|-------------------------------|-----------------------------|--------------------|
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5 th    |&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;    105    | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;60                    | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*yes*
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6 th		            |  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;120     |     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;72        |&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*yes*
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7 th| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;115            | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;79       |&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *no* |
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8 th         | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 99 | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;82 |&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *no*    

In order to get a more accurate jitter average and avoid sending false/premature alarms when the connection is just starting, the program will start to decide to notify a jitter variation to the user **from the 5 th packet on**.    

# Testing
The Makefile is provided with a **test** option, but in order to correcly run it, you have to install two more things: [nmap](https://nmap.org/nping/) and [xterm](https://linux.die.net/man/1/xterm).
To install them,**on Ubuntu**, just type in your terminal:    
`sudo apt install nmap` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; `sudo apt-get install -y xterm`    

Nmap is a open source tool for packet network generation.    
xterm is a unix-like terminal emulator.

**Type `make test` to start the test**.    
It consists in starting various TCP communications to generate some network traffic meanwhile this tool is running, to let the sniffing start.





## Credits    
This little project has been a fun experience made as a team by [Alessandro Niccolini](https://github.com/alexnicco98), [Kostantino Prifti](https://github.com/Elkosta) and [Andrea Boccone](https://github.com/Crostatus).  🍻  
