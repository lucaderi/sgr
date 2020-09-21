CC = gcc
CFLAGS += -Wall -pedantic
objects = ./src/jitter3.o ./src/gnuplot_i.o ./src/jitter_data.o ./src/time_tools.o
TARGET = ./bin/jitter

.PHONY: all test clean

./bin/jitter : $(objects)
	$(CC) -I ./headers $(CFLAGS) $^ -o $@ -lpcap

./src/jitter3.o : ./src/jitter3.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/gnuplot_i.o : ./src/gnuplot_i.c
	$(CC) -I ./headers -c $(CFLAGS) -w $^ -o $@

./src/jitter_data.o : ./src/jitter_data.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/time_tools.o : ./src/time_tools.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

all : $(TARGET)

test:	./bin/jitter
	@echo "Eseguo il test, mandare SIGINT per interrompere"
	sudo ./bin/jitter
	@echo "Test OK"

test1:	./bin/myprog
	@echo "Eseguo il test1, catturo 50 pacchetti"
	sudo ./bin/jitter 50
	@echo "Test1 OK"

clean:
	@echo "Removing garbage."
	-rm -f ./bin/jitter
	-rm -f ./src/*.o
	-rm -f *.txt
