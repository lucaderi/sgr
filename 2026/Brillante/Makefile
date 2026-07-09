CC      = gcc

NDPI_ROOT  ?= $(HOME)/nDPI-dev
NDPI_INC   = $(NDPI_ROOT)/src/include
NDPI_LIB   = $(NDPI_ROOT)/src/lib/libndpi.a
NDPI_THIRD = $(NDPI_ROOT)/src/lib/third_party/include

CFLAGS  = -Wall -Wextra -O2 -std=gnu99 -I$(NDPI_INC) -I$(NDPI_THIRD)
LDLIBS  = -lpcap -lm

PROGRAM = monitor_appProto
PREFIX  = /usr/local

all: $(PROGRAM)

$(PROGRAM): monitor_appProto.o $(NDPI_LIB)
	$(CC) monitor_appProto.o $(NDPI_LIB) -o $(PROGRAM) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Se libndpi.a non esiste ancora, compila nDPI automaticamente
$(NDPI_LIB):
	cd $(NDPI_ROOT) && ./autogen.sh && $(MAKE)

install: $(PROGRAM)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $(PROGRAM) $(DESTDIR)$(PREFIX)/bin/
	chmod +x $(DESTDIR)$(PREFIX)/bin/$(PROGRAM)

clean:
	rm -f *.o $(PROGRAM)

.PHONY: all install clean