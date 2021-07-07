SHELL := /bin/bash
CC	=  python3

.PHONY: sniffer_prot7 sniffer_ip

all: sniffer

run : app.py
	sudo $(CC) app.py
	
force_close:
ifeq (./PID.txt,$(wildcard ./PID.txt))
	    sudo kill -10 $$(cat PID.txt)
endif
ifeq (,$(wildcard ./PID.txt)) #If there is no object file
		echo "Prima esegui 'make run'" #If there is no object file
endif
