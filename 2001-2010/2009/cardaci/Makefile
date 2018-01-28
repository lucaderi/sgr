CC=gcc
CFLAGS=-Wall -pedantic -I/tmp/include/ ###
LDFLAGS=-lpcap -pthread -lmicrohttpd -L/tmp/lib/ ###

.PHONY: clean cleanall bak foo

# EXE #
my-pcap: /tmp/lib/libmicrohttpd.a analysis.o capture.o flow.o hash-table.o httpd.o my-pcap.o rrd.o ###

/tmp/lib/libmicrohttpd.a /tmp/include/microhttpd.h:
	./lib-install.sh

# OBJECTS #
analysis.o: analysis.c rrd.h analysis.h flow.h
capture.o: capture.c analysis.h capture.h
flow.o: flow.c hash-table.h flow.h httpd.h
hash-table.o: hash-table.c hash-table.h flow.h
httpd.o: httpd.c httpd.h flow.h rrd.h /tmp/include/microhttpd.h
my-pcap.o: my-pcap.c rrd.h capture.h analysis.h flow.h httpd.h
rrd.o: rrd.c rrd.h

# LATEX #
my-pcap.pdf: my-pcap.tex
	pdflatex -shell-escape my-pcap.tex
	pdflatex -shell-escape my-pcap.tex

# UTILS #
clean:
	rm -f *~ *.{o,rrd,png,aux,log,out} *dot2tex*

cleanall: clean
	rm -f my-pcap my-pcap.pdf

bak: cleanall
	make my-pcap.pdf
	make clean
	tar -zcf my-pcap.tar.gz *
