# Path a nDPI
NDPI_PATH = src/utils/ndpi/src
NDPI_INCLUDE = $(NDPI_PATH)/include/
NDPI_LIB = $(NDPI_PATH)/lib/

# Path a RRDTool (sostituisci se diverso)
RRD_INCLUDE = /opt/homebrew/include
RRD_LIB = /opt/homebrew/lib

# Compiler
CC = gcc
CFLAGS = -I$(NDPI_INCLUDE) -I$(RRD_INCLUDE) -Wall -O2 -lpthread
LDFLAGS = $(NDPI_LIB)/libndpi.a -L$(RRD_LIB) -lrrd -lnetsnmp


# File sorgente
SRC = src/port_similarity.c
OUT = src/port_similarity

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run-local: $(OUT)
	./$(OUT) -l

clean:
	rm -f $(OUT)
