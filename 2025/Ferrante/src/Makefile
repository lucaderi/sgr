# Path a ndpi
NDPI_INCLUDE = /opt/homebrew/opt/ndpi/include
NDPI_LIB = /opt/homebrew/opt/ndpi/lib

# Path a RRDTool (sostituisci se diverso)
RRD_INCLUDE = /opt/homebrew/include
RRD_LIB = /opt/homebrew/lib

# Compiler
CC = gcc
CFLAGS = -I$(NDPI_INCLUDE) -I$(RRD_INCLUDE) -Wall -O2 -lpthread
LDFLAGS = -L$(NDPI_LIB) -lndpi -L$(RRD_LIB) -lrrd -lnetsnmp


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

# Compilazione programma
$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run-remote: all
	./$(OUT) -h 200.58.174.254 -v -z

run-local: all
	./$(OUT) -l -v -z -S 10

run-test: all
	./gentest.sh
	./$(OUT) -v -z -c $(TEST) -t 100

clean:
	rm -f $(OUT)
	rm -rf $(RRDS)
	rm -rf $(TEST)
