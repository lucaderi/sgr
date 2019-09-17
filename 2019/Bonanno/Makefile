CC = gcc
CFLAGS = -Wall -pedantic

.PHONY: clean

sniffer: sniffer.o parser.o hash.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

sniffer.o: sniffer.c parser.h

parser.o: parser.c parser.h

hash.o: hash.c hash.h

clean:
	@echo "Removing garbage"
	-rm -f *.o
	-rm -f report.js
	-rm -f sniffer
