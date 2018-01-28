PCAP_DIR=./libpcap-1.0.0-ring

Sniffit: Sniffit.c
	gcc -g -I $(PCAP_DIR) Sniffit.c  -o mysniffer -lpthread $(PCAP_DIR)/libpcap.a -lpcap

clean:
	\rm -f *~ Sniffit
