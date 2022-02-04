CC = gcc
CFLAGS = -Wall -pedantic
sources = sfd.c rrd.h
libs = -lpthread -lpcap -lrrd
sfd: $(sources)
	$(CC) $< $(CFLAGS) $(libs) -o sfd
