# Jitter - a simple network monitoring tool        
![GitHub repo size](https://img.shields.io/github/repo-size/Crostatus/Jitter) ![GitHub](https://img.shields.io/github/license/Crostatus/Jitter) ![GitHub top language](https://img.shields.io/github/languages/top/Crostatus/Jitter?color=red)
 
 ## Introduction   
 **Disclaimer:** *this program is not for professional use. It has been written only for educational purpose, as an assignment project for the Network Management course at [Unipi](https://di.unipi.it/).*

This is a sniffer example using [libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) to analyze the communication frequency of TCP streams.    
libpcap is a portable C/C++ library for network traffic capture. ([GitHub repository](https://github.com/the-tcpdump-group/libpcap))

**What does the jitter measure?** The jitter is defined as the *variation* in the delay (or latency) of received packets.

This program aims to see the jitter of TCP comunications happening from/to the host machine, and detects suspicious jitter variation. 
In this text we will try to cover and explain the essential components of this program and how it works in the following order: 
 1. **[Project structure](#project-structure)**
 2. **[How to build it](#how-to-build-it)**
 3. **[Program usage](#program-usage)**    
  
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Credits](#credits)**
 
 ## Project structure
This is a quite small project, but it's never a bad idea to give a general overview for a better file exploration.     
📁bin    
&nbsp;&nbsp;&nbsp;&nbsp; ⚙️jitter &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *executable file*

📁headers    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter_data.h    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃time_tools.h    

📁src    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter.c &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *main packet capture loop*   
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃jitter_data.c &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *data structure to store sniffed packets*    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;📃time_tools.c  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *implements time related methods (e.g get elapsed time)*  

🛠️Makefile &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *project builder*    

## How to build it
In order to compile this project, you need to have [libpcap](https://github.com/the-tcpdump-group/libpcap) (*v 1.9.1-3 or newer*) and [gnuplot](http://www.gnuplot.info/) (*v 5.2 or newer*) installed.    
One way to easily get it, **on Ubuntu**, is to use the following commands:    
`sudo apt-get install libpcap-dev`&nbsp;&nbsp;&nbsp;`sudo apt-get install gnuplot`    

To check your current version:    
`apt-cache show libpcap-dev` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`gnuplot-V`
    
That's it! Now you can use the Makefile to get everything done, just run `make` in the project folder and you are ready to go.     

## Program usage
This program, once started, can capture packets *endlessly* or *stop once a default amount has been reached*. 
Those two ways to run can are determined by the value of the only parameter that this program accepts:

|NAME                |TYPE                       |OPTIONAL                         |
|----------------|-------------------------------|-----------------------------|
|packet_number|Non negative integer            |yes         |

**Examples**:    
Running `sudo ./bin/jitter 50` will stop after capturing the next 50 packets.    
If no **packet_number** is provided, so just running `sudo ./bin/jitter` will start sniffing non-stop.

**In both cases** it can be correctly stopped sending a **SIGINT** (*Ctlr + c*) interruption to this process.

Once that the sniffing has stopped, a very simple menu will show up to see the collected data.    

## Credits    
This little project has been a fun experience made as a team by [Alessandro Niccolini](https://github.com/alexnicco98), [Kostantino Prifti](https://github.com/Elkosta) and [Andrea Boccone](https://github.com/Crostatus).  🍻  
