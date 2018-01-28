#PCAP_DIR=./libpcap-0.9.8

MoriSniffer: MoriSniffer.c
#	gcc -g -I $(PCAP_DIR) MoriSniffer.c -o MoriSniffer $(PCAP_DIR)/libpcap.a 
	gcc -g  MoriSniffer.c -o MoriSniffer -lpcap 

clean:
	\rm -f *~ MoriSniffer
