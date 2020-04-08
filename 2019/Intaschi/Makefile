CC		         =  gcc
AR               =  ar
CFLAGS	        += -std=c99 -Wall -pedantic -g
ARFLAGS          =  rvs
INCLUDES	     = -I.
LDFLAGS 	     = -L.
OPTFLAGS	     = #-O3 
LIBS             = -lpaho-mqtt3c -lcurl

TARGETS		     = mqttmonitor

OBJECTS		     = configuration.o database.o

INCLUDE_FILES    = configuration.h database.h

SRC_FILES        = configuration.c database.c mqttmonitor.c

CONF_FILE        = mqttmonitor.conf

.PHONY: cleanall tar zip
.SUFFIXES: .c .h

%: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $@ $< $(LDFLAGS) 

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $<

mqttmonitor: mqttmonitor.o mylib.a $(INCLUDE_FILES)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

mylib.a: $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

cleanall:
	rm -f mqttmonitor
	\rm -f *.o
	\rm -f mylib.a
	\rm -f mqttmonitor.tar
	\rm -f mqttmonitor.zip

tar:
	tar -cf mqttmonitor.tar $(INCLUDE_FILES) $(SRC_FILES) $(CONF_FILE) Makefile

zip:
	zip -r mqttmonitor.zip $(INCLUDE_FILES) $(SRC_FILES) $(CONF_FILE) relazione.pdf MQTTMonitor.json Makefile
