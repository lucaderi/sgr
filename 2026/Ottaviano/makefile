CC = gcc
CFLAGS = -Wall 

all: mybridge sender pcount

pcount: pcount.o
	$(CC) $(CFLAGS) -o pcount pcount.o -lpcap

sender: sender.o 
	$(CC) $(CFLAGS) -o sender sender.o -lpcap

mybridge: mybdrige.o utils.o
	$(CC) $(CFLAGS) -o mybridge mybridge.o utils.o -lpcap

mybdrige.o: mybridge.c utils_leaky_bucket.h
	$(CC) $(CFLAGS) -c mybridge.c

pcount.o: pcount.c structure.h
	$(CC) $(CFLAGS) -c pcount.c

sender.o: sender.c structure.h
	$(CC) $(CFLAGS) -c sender.c

utils.o: utils.c utils_leaky_bucket.h structure.h
	$(CC) $(CFLAGS) -c utils.c

clean:
	rm -f *.o mybridge sender pcount
