_DEBUG=-DDEBUG -DDEBUG_LATENCY -DDEBUG_SIMULATE
DEBUG=-g
_DT_FLAGS=-DNOPACKETLOST
DT_FLAGS=

CC=gcc
CFLAGS=-Wall -pedantic $(DEBUG) #-std=c99 
LIBS=-lpcap -lm

OBJ=deviceTester.o deviceTester_impl.o printPcap.o tests.o timeUtils.o
BIN=deviceTester printPcap tests
INSTALL_DIR=/usr/local/bin

.PHONY: all install disinstall clean doTests doDeviceTester

# Default
all: ${BIN}

# Objects
deviceTester.o: deviceTester.c utils.h timeUtils.h types.h deviceTester.h 

deviceTester_impl.o: deviceTester_impl.c utils.h timeUtils.h types.h \
  deviceTester.h

printPcap.o: printPcap.c types.h deviceTester.h utils.h timeUtils.h

tests.o: tests.c utils.h deviceTester.h types.h

timeUtils.o: timeUtils.c types.h timeUtils.h



# Binaries
deviceTester: deviceTester.o deviceTester_impl.o timeUtils.o
	gcc $(DEBUG) deviceTester.o deviceTester_impl.o timeUtils.o -o deviceTester $(LIBS)

printPcap: printPcap.o deviceTester_impl.o timeUtils.o
	gcc $(DEBUG) $^ -o $@ $(LIBS)

tests: tests.o deviceTester_impl.o timeUtils.o	
	gcc $(DEBUG) tests.o deviceTester_impl.o timeUtils.o -o tests $(LIBS)

# Phonys
clean:
	-rm -f *.o *~ a.out

install: deviceTester
	cp deviceTester ${INSTALL_DIR}

disinstall:
	-rm -f ${INSTALL_DIR}/deviceTester

doDeviceTester:
	make clean
	make deviceTester
	./deviceTester
	if [ $? = 0 ] ; then  echo ok ; fi

doTests:
	make clean
	make tests
	./tests
	if [ $? = 0 ] ; then echo "tests superati" ; fi
