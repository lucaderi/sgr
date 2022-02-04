# Variabili predefinite

CC = gcc
CFLAGS = -Wall -pedantic

# Variabili

#device = wlp2s0
lib = -lpcap -lm
cJSON = cJSON-master/



sonda: sonda.c support.o $(cJSON)cJSON.o 
	$(CC) $(CFLAGS) $^ $(lib) -o $@

support: support.c support.h
	$(CC) $(CFLAGS) -c $<

cJSON: $(cJSON)cJSON.c $(cJSON)cJSON.h
	$(CC) $(CFLAGS) -c $<

.PHONY: clean monitor json

clean:
	@echo "Removing garbage"
	-rm *~ *.o $(cJSON)*.o




