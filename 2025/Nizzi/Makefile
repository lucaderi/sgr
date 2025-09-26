# Nome del compilatore
CC = gcc

# Opzione di compilazione
CFLAGS = -g

# Libreria da linkare			
LDFLAGS = -lpcap 

# File sorgente
SCOUNT_SRC = RilevatoreSynScan.c
PCOUNT_SRC = Scan.c

# Nomi degli eseguibili
SCOUNT_EXEC = RilevatoreSynScan
PCOUNT_EXEC = Scan

# Target predefinito
all: $(SCOUNT_EXEC) $(PCOUNT_EXEC)

# Compilazione degli eseguibili
$(SCOUNT_EXEC): $(SCOUNT_SRC) 
	$(CC) $(CFLAGS) -o $(SCOUNT_EXEC) $(SCOUNT_SRC) $(LDFLAGS)

$(PCOUNT_EXEC): $(PCOUNT_SRC) 
	$(CC) -o $(PCOUNT_EXEC) $(PCOUNT_SRC)

# Pulizia dei file generati
clean:
	rm -f $(SCOUNT_EXEC) $(PCOUNT_EXEC)

# Dichiarazione di target fittizi (non-file)
.PHONY: all clean
