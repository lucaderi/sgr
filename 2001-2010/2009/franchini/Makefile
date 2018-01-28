PCAP_DIR=./libpcap-0.9.8

all: franchiniSniffer

clean:
	\rm -f *~ franchiniSniffer

franchiniSniffer: franchiniSniffer.c
#	gcc -g -I $(PCAP_DIR) franchiniSniffer.c -o franchiniSniffer $(PCAP_DIR)/libpcap.a
	gcc -g franchiniSniffer.c hash.c -o franchiniSniffer -lpcap