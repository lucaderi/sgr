CC		=  gcc
AR              =  ar
ARFLAGS         =  rvs
INCLUDES	= -I.
LDFLAGS 	= -L.
OPTFLAGS	= 
LIBS            = -pthread -lpcap -lm

TARGETS		= arpscan

OBJECTS		= hasht.o hasht_DB.o

INCLUDE_FILES   = hasht.h hasht_DB.h

.PHONY: all clean cleanall
.SUFFIXES: .c .h

%: %.c
	$(CC) $(INCLUDES) $(OPTFLAGS) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(INCLUDES) $(OPTFLAGS) -c -o $@ $<

all		: $(TARGETS)

arpscan: arpscan.o lib.a $(INCLUDE_FILES)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

lib.a: $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

clean		:
	rm -f $(TARGETS)

cleanall	: clean
		\rm -f *.o *~ lib.a
