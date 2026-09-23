CC = cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS ?= -lcap

.PHONY: all debug clean

all: netmon

netmon: netmon.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -g -O0"

clean:
	$(RM) netmon
