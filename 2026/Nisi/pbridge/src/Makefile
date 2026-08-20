CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap
BINDIR  = ../bin
TARGETS = $(BINDIR)/psend $(BINDIR)/pcount $(BINDIR)/pbridge

all: $(BINDIR) $(TARGETS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/psend: psend.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/pcount: pcount.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/pbridge: pbridge.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
