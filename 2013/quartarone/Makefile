CFLAGS = 
CC = gcc
LIBS = pcap
LDFLAGS = -lpcap -lrrd -lpthread
OBJECTS = pktUtils.o sniffer.o data.o rrdstats.o flow.o

all: qsniffer

qsniffer: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

pktUtils.o: pktUtils.c pktUtils.h sniffer.h
	$(CC) $(CFLAGS) -c $< -o $@

stats.o: data.c data.h 
	$(CC) $(CFLAGS) -c $< -o $@

sniffer.o: sniffer.c sniffer.h pktUtils.h data.h rrdstats.h flow.h
	$(CC) $(CFLAGS) -c $< -o $@

rrdstats.o: rrdstats.c rrdstats.h data.h
	$(CC) $(CFLAGS) -c $< -o $@

flow.o: flow.c flow.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f qsniffer *.o *~
