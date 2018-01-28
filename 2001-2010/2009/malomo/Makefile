CFLAGS = -Wall -pedantic -g
CC = cc
LIBS = pcap
LDFLAGS = -lpcap -lrrd
OBJECTS = utils.o sniffer.o stats.o rrdstats.o flow.o

all: malSniffer

malSniffer: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c $< -o $@

stats.o: stats.c stats.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

sniffer.o: sniffer.c sniffer.h utils.h stats.h rrdstats.h flow.h
	$(CC) $(CFLAGS) -c $< -o $@

rrdstats.o: rrdstats.c rrdstats.h stats.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

flow.o: flow.c flow.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f malSniffer *.o *~
