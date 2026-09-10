CC=gcc
CFLAGS=-Wall -O2

all: collector flow_generator

collector: collector.c
	$(CC) $(CFLAGS) -o collector collector.c

flow_generator: flow_generator.c
	$(CC) $(CFLAGS) -o flow_generator flow_generator.c

clean:
	rm -f collector flow_generator
