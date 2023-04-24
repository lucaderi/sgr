CC=gcc
CFLAGS= -Wall 

main: main.c dependencies.h
	$(CC) $(CFLAGS) main.c dependencies.h senderUDP.c senderUDP.h -o phammer

clean:
	rm -f *.o