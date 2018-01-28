### Makefile for project capture-2.0 ###

all: hashtable.o flow.o cbuffer.o rrd.o httpd.o capture.o
	gcc -g -Wall --pedantic hashtable.o flow.o cbuffer.o rrd.o httpd.o capture.o -o capture -lpcap -lpthread -lmicrohttpd
	

capture.o: rrd.h capture.h cbuffer.h capture.c
	gcc -g -Wall --pedantic -c capture.c -o capture.o
	
rrd.o: rrd.h rrd.c
	gcc -g -Wall --pedantic -c rrd.c -o rrd.o
	
httpd.o: HTTPinterface.h capture.h httpd.c
	gcc -g -Wall --pedantic -c HTTPinterface.c -o httpd.o
	
cbuffer.o: cbuffer.h cbuffer.c
	gcc -g -Wall --pedantic -c cbuffer.c -o cbuffer.o
	
flow.o: flow.h capture.h
	gcc -g -Wall --pedantic -c flow.c -o flow.o
	
hashtable.o: hashtable.h flow.h
	gcc -g -Wall --pedantic -c hashtable.c -o hashtable.o
	
clean:
	\rm *.o capture