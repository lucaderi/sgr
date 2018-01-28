all: main.c formats.h
	gcc -pthread -Wall -O3 main.c -o main.o -lpcap

clean:
	-rm *.o log/*.log
