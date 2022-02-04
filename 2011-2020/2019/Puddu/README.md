# nDPI-warpper

nDPI-wrapper is a python wrapper for the nDPI library, and allows you to analyse data mostly without having to use C code.

## Getting Started

These instructions will allow you to set up and run a copy of the project on your local machine for development and testing purposes. Firstly, compile nDPI following the instructions in the README.md file, on the nDPI folder.

### Prerequisites

This software has been tested under python 3.5, but every python version higher or equal 3 would also be suitable. To execute the ndpi_example.py you also need to install scapy

### Installing

Navigate to the folder nDPI/ and create a folder containing all the file of my project. Then, navigate into this folder, and write

```
. ./automatic.sh
```

To test it, use

```
python3 ndpi_example.py <interface>
```

or 

```
python3 ndpi_example.py <pcap_file>
```

### More information
To have a closer look at my wrapper see the ndpi_wrapper.pdf file
