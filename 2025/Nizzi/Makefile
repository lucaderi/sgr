#Nome del compilatore
CC = gcc

# Librerie da linkare			
LDFLAGS = -lpcap 

#File sorgente
PCOUNT_SRC = RilevatorePortScan.c

#Nomi dell’eseguibile
PCOUNT_EXEC = RilevatorePortScan

# Target predefinito
all: $(PCOUNT_EXEC)

# Compilazione dell’eseguibile
$(PCOUNT_EXEC): $(PCOUNT_SRC) 
	$(CC) -g -o $(PCOUNT_EXEC) $(PCOUNT_SRC) $(LDFLAGS)

# Pulizia dei file generati
clean:
	rm $(PCOUNT_EXEC)

# Dichiarazione di target fittizi (non-file)
.PHONY: all clean
