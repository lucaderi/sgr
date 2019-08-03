# nDPI-warpper

nDPI-wrapper is a python wrapper for the nDPI library, and allows you to analyse data mostly without having to use C code.

## Getting Started

These instructions will allow you to set up and run a copy of the project on your local machine for development and testing purposes. Firstly, compile nDPI following the instructions in the README.md file, on the nDPI folder.

### Prerequisites

This software has been tested under python 3.5, but every python version higher or equal 3 would also be suitable

### Installing

Navigate to the folder /example/ and extract all the files of the nDPI-wrapper contained in the folder. Then, create a shared library, by typing

```
make -f Makefile.wrap
```

To test it, just use

```
python3 ndpi_Reader_wrap.py -i <interface>
```

Alternatively, run it like this and see what it can offer you

```
python3 ndpi_Reader_wrap.py
```

### More information
To have a closer look at my wrapper see the ndpi_wrapper.pdf file
