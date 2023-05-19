CC=gcc
CFLAGS=-g -Wall -O -std=c99
LDLIBS=-lrt -L./nDPI/src/lib -l:libndpi.a -lm

EXEC=main.out tool.out toolDisk.out 

all: $(EXEC)

%.out: %.o 
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c  
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(EXEC) *.o  
