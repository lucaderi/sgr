# Path a nDPI
NDPI_PATH = utils/ndpi/src
NDPI_INCLUDE = $(NDPI_PATH)/include/
NDPI_LIB = $(NDPI_PATH)/lib/
NDPI_MAKE = utils/ndpi/

# Path a RRDTool (sostituisci se diverso)
RRD_INCLUDE = /opt/homebrew/include
RRD_LIB = /opt/homebrew/lib

# Compiler
CC = gcc
CFLAGS = -I$(NDPI_INCLUDE) -I$(RRD_INCLUDE) -Wall -O2 -lpthread
LDFLAGS = $(NDPI_LIB)/libndpi.a -L$(RRD_LIB) -lrrd -lnetsnmp


# File sorgente
SRC = port_similarity.c
OUT = port_similarity
RRDS = rrds/
GENTEST = test/prova.sh
TEST = test/

# Regole principali
all: $(OUT)
	mkdir -p $(TEST)
	mkdir -p $(RRDS)

# Regola per build nDPI
ndpi-build:
	cd $(NDPI_MAKE) && ./autogen.sh --with-only-libndpi
	$(MAKE) -C $(NDPI_MAKE)

# Compilazione programma (dopo ndpi-build)
$(OUT): $(SRC) ndpi-build
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run-remote:
	./$(OUT) -h 200.58.174.254 -v -z

run-local:
	./$(OUT) -l -v -z -S 10

run-test:
	./$(OUT) -v -z -c $(TEST) -t 100

clean:
	rm -f $(OUT)
	rm -rf $(RRDS)
	rm -rf $(TEST)
	$(MAKE) -C $(NDPI_MAKE) clean
