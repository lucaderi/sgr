PF_RING_HOME=$(HOME)/PF_RING
LIB=-L $(PF_RING_HOME)/userland/lib -lpfring -lrt
FILES=dnastack.o arp.o udp.o read.o send.o pkt_ring.o hashtable.o socket.o
DEFINES=-D_GNU_SOURCE -DHAVE_PCAP
INCLUDES=-I $(PF_RING_HOME)/userland/lib
CC=gcc -g -O2 -Wall -W -Werror -pipe $(INCLUDES) $(DEFINES) -fPIC
TEST=hashtable_test

#####

.PHONY: all clean

all: dnastack.so test

test: $(TEST)

dnastack.so: $(FILES)
	$(CC) -shared -o $@ $(FILES) $(LIB) -ldl 

socket.o:
dnastack.o:
arp.o:
send.o:
udp.o:
read.o:
pkt_ring.o:
hashtable.o:

hashtable_test: hashtable.o hashtable_test.c
	$(CC) -o $@ $^
	./hashtable_test

clean:
	- rm -f *~ *.o *.so hashtable_test

