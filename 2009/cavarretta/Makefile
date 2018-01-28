CFLAGS = -Wall -pedantic
CC = cc
LDFLAGS = -lpcap -lrrd -lpthread -levent
OBJECTS = sniffer.o timer.o arrayqueue.o hashtable.o cemetery.o flow.o pkt_info.o

all: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o Sniffer

sniffer.o: sniffer.c sniffer.h pkt_info.h timer.h arrayqueue.h cemetery.h pkt_info.h hashtable.h flow.h
	$(CC) $(CFLAGS) -c $< -o $@

timer.o: timer.c timer.h flow.h pkt_info.h sniffer.h arrayqueue.h cemetery.h hashtable.h
	$(CC) $(CFLAGS) -c $< -o $@

arrayqueue.o: arrayqueue.c arrayqueue.h pkt_info.h
	$(CC) $(CFLAGS) -c $< -o $@

hashtable.o: hashtable.c hashtable.h flow.h pkt_info.h
	$(CC) $(FLAGS) -c $< -o $@

cemetery.o: cemetery.c cemetery.h hashtable.h flow.h pkt_info.h
	$(CC) $(FLAGS) -c $< -o $@

flow.o: flow.c flow.h pkt_info.h
	$(CC) $(CFLAGS) -c $< -o $@

pkt_info.o: pkt_info.c pkt_info.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f Sniffer *.o *~
