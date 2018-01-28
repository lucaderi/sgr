CC=gcc -g -O2 -Wall -W -pipe
EXEC= udp_stress udp_cat udp_send udp_echo udp_count udp_file

#####

.PHONY: all clean

all: $(EXEC)

clean:
	- rm -f *~ *.o *.pyc $(EXEC) 2> /dev/null

udp_send: udp_send.c

udp_cat: udp_cat.c

udp_echo: udp_echo.c
	$(CC) $^ -o $@ -lpthread

udp_count: udp_count.c

udp_stress: udp_stress.c
	$(CC) $^ -o $@ -lpthread

udp_file: udp_file.c
	$(CC) $^ -o $@ -lpthread