CC = gcc
CFLAGS += -std=c99 -Wall -pedantic
LIBS = -lpcap -lpthread
OBJ = macToVendor.o harper.o ipMacList.o

%.o: %.c
	$(CC) -c -o $@ $< -DDEBUG

harper: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f harper *.o *.txt *.csv

.PHONY: clean
