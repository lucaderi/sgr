FORMATS = formats.h formats.c
ANALYZER = analyzer.h analyzer.c
CFLAGS = -pthread -Wall -g -O3

backfire: main.c $(ANALYZER) $(FORMATS) Makefile
	gcc $(CFLAGS) formats.c analyzer.c main.c -o backfire -lpcap -lncurses

clean:
	-rm -f *.o log/*.log backfire *~
