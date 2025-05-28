#Nome del compilatore
CC = gcc

#Opzioni di compilazione
CFLAGS = -Wall -Wpedantic -lpcap -lm -lndpi

#File sorgente
PCOUNT_SRC = pcount.c

#Nomi degli eseguibili
PCOUNT_EXEC = pcount

#Per completare l'operazione devono essere generato l'eseguibile
all: $(PCOUNT_EXEC)

#Per creare l'eseguibile abbiamo bisogno del file-sorgente (PCOUNT_SRC)
$(PCOUNT_EXEC): $(PCOUNT_SRC) 
	$(CC) $(PCOUNT_SRC) -o $(PCOUNT_EXEC) $(CFLAGS)

#Pulizia: elimina i file eseguibili
clean:
	rm $(PCOUNT_EXEC)