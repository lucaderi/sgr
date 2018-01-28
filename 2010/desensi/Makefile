
CC                   = gcc 
CXX 		     = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O6 -finline-functions#-fno-inline
CXXFLAGS             = -Wall -DTRACE_FASTFLOW -g
CFLAGS               =
LDFLAGS              = 
INCS                 = -I./fastflow
LIBS                 = -lpthread -lpcap
INCLUDES             =
TARGET               = ffProbe

.PHONY: all clean cleanall install uninstall
.SUFFIXES: .cpp .o

ffProbe.o: ffProbe.cpp *.hpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -c -o $@ $<

all: $(TARGET)

ffProbe: ffProbe.o
	$(CXX) ffProbe.o -o ffProbe $(CXXFLAGS) $(LIBS)
clean: 
	-rm -fr *.o *~
cleanall: clean
	-rm -fr $(TARGET)
install:
	cp ./ffProbe /usr/local/bin/ffProbe
uninstall:
	rm -fr /usr/local/bin/ffProbe
