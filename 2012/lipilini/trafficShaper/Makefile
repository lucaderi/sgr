#
# Makefile for trafficShaper
#
# Jacopo Lipilini
#

# Compiler
CPP = gcc -g

# Options
PF_RING_HOME = /home/jacopo/Desktop/PF_RING
CPPFLAGS = -Wall -pedantic -I $(PF_RING_HOME)/userland/lib


# Rules

.PHONY : all
all: trafficShaper.o

trafficShaper.o: tsTypes.h trafficShaper.h trafficShaper.c
	$(CPP) $(CPPFLAGS) -c $^

.PHONY : clean
clean:
	rm -f *.gch *~ *.o
