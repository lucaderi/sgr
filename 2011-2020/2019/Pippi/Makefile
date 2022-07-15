CC		= gcc
CFLAGS	= -g -Wall

.PHONY	= test

sflowtoinflux: sflowtoinflux_pipe.c
	$(CC) $(CFLAGS) $< -o $@	
	tar -xzvf ./InMon_Agent-6_4.tgz

test:	
	make -C ./InMon_Agent-6.4/
	./test.sh
