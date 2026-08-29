CC=gcc

NDPI_CFLAGS := $(shell pkg-config --cflags libndpi 2>/dev/null || echo -I/usr/include/ndpi -I/usr/local/include/ndpi)
NDPI_LIBS := $(shell pkg-config --libs libndpi 2>/dev/null || echo -lndpi)

CFLAGS=-Wall -g -O3 $(NDPI_CFLAGS)
LDLIBS=$(NDPI_LIBS) -lpcap -lcap -lm -lrt

TARGET=vpnFlows_detector

all: $(TARGET)

vpnFlows_detector: vpnFlows_detector.c makefile
	$(CC) $(CFLAGS) vpnFlows_detector.c -o vpnFlows_detector.out $(LDLIBS)

# ---BATTERIE DI TESTS---
test1:
	./vpnFlows_detector.out -i testVPN/Test-noVPN.pcap

test2:
	./vpnFlows_detector.out -i testVPN/Test1-conVPN.pcap

clean:
	rm -f *.o *.out