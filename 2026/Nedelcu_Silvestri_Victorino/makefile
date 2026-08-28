CC=gcc
CFLAGS=-Wall -g -O3 -pthread -lpcap -lcap -lndpi
LDLIBS=-lm -lrt -pthread

TARGET=vpnFlows_detector

all: $(TARGET)

vpnFlows_detector: vpnFlows_detector.c makefile
	$(CC) -Wall vpnFlows_detector.c -o vpnFlows_detector.out $(CFLAGS) $(LDLIBS)

# BATTERIE DI TESTS
test1:
	sudo ./vpnFlows_detector.out -i testVPN/Test-noVPN.pcap

test2:
	sudo ./vpnFlows_detector.out -i testVPN/Test1-conVPN.pcap

clean:
	rm -f *.o *.out