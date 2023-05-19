CC=gcc
CFLAGS=-g -Wall -O -std=c99
LDLIBS=./nDPI/src/lib/libndpi.a -lm -lrt

EXEC=main tool toolDisk

all: $(EXEC)

main: main.c predict.o
	$(CC) $(LDFLAGS) $< predict.o -o $@ $(LDLIBS)

tool: tool.c predict.o
	$(CC) $(CFLAGS) $< predict.o -o $@ $(LDLIBS)

toolDisk: toolDisk.c predict.o
	$(CC) $(CFLAGS) $< predict.o -o $@ $(LDLIBS)

predict.o: predict.c  
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm -f $(EXEC) *.o  
