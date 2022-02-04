#***************************************************
#Progetto Gestione di reti
#Modulo    : MAKEFILE
#Autori    : Bianucci Marco			(464134),
#            Lupone Nicolas Emilio	(490591),
#            Poggi Andrea			(524864),
#            Tola Stefania 			(293145).
#
CC = gcc
#CFLAGS  = -Wall -pedantic 
CFLAGS  = -Wall -g -pedantic
LIBS = -pthread -lpcap -lprocps

#pony
.PHONY: clean debug all compile 

# dipendenze eseguibili: oggetti e/o librerie
all: ThDemon.o ThScan.o ThPut.o arrQueue.o intQueue.o network_monitoring

network_monitoring: network_monitoring.o ThScan.o arrQueue.o ThPut.o ThDemon.o int_list.o intQueue.o
	$(CC) -Wall -pedantic -o $@ $^ $(LIBS)

network_monitoring.o: network_monitoring.c network_monitoring.h  mycmacro.h Global.h ThDemon.h ThPut.h

ThDemon.o: ThDemon.c ThDemon.h intQueue.o

ThScan.o: ThScan.c ThScan.h 

ThPut.o: ThPut.c ThPut.h 

arrQueue.o: arrQueue.c arrQueue.h

intQueue.o: intQueue.c intQueue.h

int_list.o: int_list.c int_list.h


compile: 
	make all

#pulizia dei file generati
clean:
	rm -f *.o *.out *~ core 
	rm -f network_monitoring Global myMutexFunc.o ThDemon.o arrQueue.o ThScan.o ThPut.o


#aggiunge a cflags la dichiarazione a compilazione della macro DEBUG_ON	
debug: CFLAGS+= -DDEBUG_BLOCK_ON
debug: all	


