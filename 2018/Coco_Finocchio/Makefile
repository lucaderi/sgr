CC = gcc
LIBS = -lpcap -pthread
TARGETS = main.c    \
          map.c

.PHONY = clean

hoker: $(TARGETS)
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f hoker
