CC = gcc
CFLAGS += -Wall -pedantic
objects = ./src/jitter3.o ./src/gnuplot_i.o ./src/jitter_data.o ./src/time_tools.o ./src/menu.o
TARGET = ./jitter

.PHONY: all test clean

./jitter : $(objects)
	$(CC) -I ./headers $(CFLAGS) $^ -o $@ -lpcap

./src/jitter3.o : ./src/jitter3.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/gnuplot_i.o : ./src/gnuplot_i.c
	$(CC) -I ./headers -c $(CFLAGS) -w $^ -o $@

./src/menu.o : ./src/menu.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/jitter_data.o : ./src/jitter_data.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

./src/time_tools.o : ./src/time_tools.c
	$(CC) -I ./headers -c $(CFLAGS) $^ -o $@

all : $(TARGET)

test:	./jitter
	@echo "Testing"
	chmod +x test.sh
	xterm -e sudo ./test.sh &
	sudo ./jitter
	@echo "Test OK"

clean:
	@echo "Removing garbage."
	-rm -f ./jitter
	-rm -f ./src/*.o
	-rm -f *.txt
