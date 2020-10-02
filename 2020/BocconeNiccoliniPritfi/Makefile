CC = gcc
CFLAGS += -Wall -pedantic
objects = ./src/jitter3.o ./src/gnuplot_i.o ./src/jitter_data.o ./src/time_tools.o ./src/menu.o
TARGET = ./jitter

.PHONY: all test clean

./jitter : $(objects)
	$(CC) -I ./headers $(CFLAGS) $^ -o $@ -lpcap -lnotify

./src/jitter3.o : ./src/jitter3.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/gnuplot_i.o : ./src/gnuplot_i.c
	$(CC) -I ./headers -c $(CFLAGS) -w $^ -o $@

./src/menu.o : ./src/menu.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/jitter_data.o : ./src/jitter_data.c
	$(CC) -I ./headers  `pkg-config --cflags --libs libnotify` -c $(CFLAGS) $^ -o $@

./src/time_tools.o : ./src/time_tools.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

all : $(TARGET)

test:	./jitter
	@echo "Eseguo il test, mandare SIGINT per interrompere"
	sudo ./jitter
	@echo "Test OK"

test1:	./myprog
	@echo "Eseguo il test1, catturo 50 pacchetti"
	sudo ./jitter 50
	@echo "Test1 OK"

clean:
	@echo "Removing garbage."
	-rm -f ./jitter
	-rm -f ./src/*.o
	-rm -f *.txt
