################# Target per la compilazione

CC = gcc
CFLAGS = -Wall -pedantic -g -lpcap -lpthread

iodiceSniffer : 
	$(CC) $(CFLAGS) iodiceSniffer.c -o iodiceSniffer

.PHONY: clean

clean : 
	rm -f *~ iodiceSniffer

cleandb : 
	rm -f *.rrd *.png

#################
