PCAP_DIR=./libpcap-1.0.0

Sniffit: Sniffit.c
	gcc -g -I $(PCAP_DIR) Sniffit.c  -o Sniffit -lpthread $(PCAP_DIR)/libpcap.a -lpcap

clean:
	\rm -f *~ Sniffit
