#
# Makefile for l7-bridge
#
# Jacopo Lipilini
#

# App name
APPNAME = l7-bridge

# Directories
ROOTDIR = ./
FHTDIR = ./flowHashTable/
OBJDIR = ./obj/
RULESDIR = ./ruleManager/
TESTDIR = ./test/
TSDIR = ./trafficShaper/
UTILSDIR = ./utils/

# Compiler
CPP = g++ -g

# Options
#PF_RING_HOME=$(HOME)/PF_RING
PF_RING_HOME = /home/jacopo/Desktop/PF_RING
#NDPI_HOME=/home/deri/nProbe/nDPI
NDPI_HOME = /home/jacopo/Desktop/nDPI
NDPI_ADDITIONAL_HEADER = -I $(NDPI_HOME)/src/lib -I $(NDPI_HOME)/src/include
LIBXMLPP_HEADER = -I /usr/lib64/libxml++-2.6/include -I /usr/lib64/glibmm-2.4/include -I /usr/include/glib -I /usr/lib64/glib-2.0/include
CPPFLAGS = -Wall -pedantic -std=c++0x $(NDPI_ADDITIONAL_HEADER) -I $(PF_RING_HOME)/userland/lib -I $(ROOTDIR) -I $(FHTDIR) -I $(UTILSDIR) -I $(RULESDIR) -I $(TSDIR)
LIBS = $(NDPI_HOME)/src/lib/.libs/libndpi.a -lnl -L $(PF_RING_HOME)/userland/libpcap -L $(PF_RING_HOME)/userland/lib -lpfring -lpcap -lpfring -lpthread -lxml++-2.6 -lxml2 -lglibmm-2.4

# Objects
FHTOBJ = flowStruct.o flowList.o flowHashTable.o
MAINOBJ = pcapAnalyzer.o trafficShaperThread.o signalHandlerThread.o monitorThread.o init.o term.o
RULESOBJ = ruleStruct.o ruleList.o ruleNode.o ruleTrie.o ruleManager.o
TSOBJ = trafficShaper.o
UTILSOBJ = mathUtil.o memUtil.o ipUtil.o flowUtil.o ruleUtil.o timeUtil.o

# Globals include
GLOBAL_INC = globalTypes.h globals.h

# Test exe
TESTEXE = test_hash_pcap test_rule


# Rules

.PHONY : all
all: main test move_obj


# TEST MAKE RULES

.PHONY: test
test: $(TESTEXE)

test_hash_pcap: $(UTILSOBJ) $(FHTOBJ) test_hash_pcap.o
	$(CPP) $(CPPFLAGS) $^ $(LIBS) -o $(TESTDIR)test_hash_pcap

test_hash_pcap.o: $(TESTDIR)test_hash_pcap.cpp
	$(CPP) $(CPPFLAGS) -c $^

test_rule: $(UTILSOBJ) $(RULESOBJ) test_rule.o
	$(CPP) $(CPPFLAGS) $^ $(LIBS) -o $(TESTDIR)test_rule

test_rule.o: $(TESTDIR)test_rule.cpp
	$(CPP) $(CPPFLAGS) $(LIBXMLPP_HEADER) -c $^


# MAIN MAKE RULES

main: $(UTILSOBJ) $(TSOBJ) $(RULESOBJ) $(FHTOBJ) $(MAINOBJ) main.o 
	$(CPP) $(CPPFLAGS) $^ $(LIBS) -o $(APPNAME)

.PHONY: obj-main
obj-main: $(MAINOBJ)

main.o: $(GLOBAL_INC) arrayQueue.h main.cpp
	$(CPP) $(CPPFLAGS) -c $^

term.o: $(GLOBAL_INC) term.cpp
	$(CPP) $(CPPFLAGS) -c $^

init.o: $(GLOBAL_INC) init.cpp
	$(CPP) $(CPPFLAGS) -c $^

monitorThread.o: $(GLOBAL_INC) monitorThread.cpp
	$(CPP) $(CPPFLAGS) -c $^

signalHandlerThread.o: $(GLOBAL_INC) signalHandlerThread.cpp
	$(CPP) $(CPPFLAGS) -c $^
	
trafficShaperThread.o: $(GLOBAL_INC) trafficShaperThread.cpp
	$(CPP) $(CPPFLAGS) -c $^

pcapAnalyzer.o: $(GLOBAL_INC) pcapAnalyzer.cpp
	$(CPP) $(CPPFLAGS) -c $^


# FLOWHASHTABLE MAKE RULES

.PHONY : obj-flowHashTable
obj-flowHashTable: $(FHTOBJ)

flowHashTable.o: $(FHTDIR)flowHashTable.h $(FHTDIR)flowHashTable.cpp
	$(CPP) $(CPPFLAGS) -c $^

flowList.o: $(FHTDIR)flowList.h $(FHTDIR)flowList.cpp
	$(CPP) $(CPPFLAGS) -c $^

flowStruct.o: $(FHTDIR)flowTypes.h $(FHTDIR)flowStruct.h $(FHTDIR)flowStruct.cpp
	$(CPP) $(CPPFLAGS) -c $^


# RULEMANAGER MAKE RULES

.PHONY : obj-ruleManager
obj-ruleManager: $(RULESOBJ)

ruleManager.o: $(RULESDIR)ruleManager.h $(RULESDIR)ruleManager.cpp
	$(CPP) $(CPPFLAGS) $(LIBXMLPP_HEADER) -c $^

ruleTrie.o: $(RULESDIR)ruleTrie.h $(RULESDIR)ruleTrie.cpp
	$(CPP) $(CPPFLAGS) -c $^

ruleNode.o: $(RULESDIR)ruleNode.h $(RULESDIR)ruleNode.cpp
	$(CPP) $(CPPFLAGS) -c $^

ruleList.o: $(RULESDIR)ruleList.h $(RULESDIR)ruleList.cpp
	$(CPP) $(CPPFLAGS) -c $^

ruleStruct.o: $(RULESDIR)ruleStruct.h $(RULESDIR)ruleStruct.cpp
	$(CPP) $(CPPFLAGS) -c $^


# TRAFFIC SHAPER MAKE RULES

.PHONY: obj-trafficShaper
obj-trafficShaper: $(TSOBJ)

trafficShaper.o: $(TSDIR)tsTypes.h $(TSDIR)trafficShaper.h $(TSDIR)trafficShaper.cpp
	$(CPP) $(CPPFLAGS) $(LIBXMLPP_HEADER) -c $^


# UTIL MAKE RULES

.PHONY: obj-utils
obj-utils: $(UTILSOBJ)

timeUtil.o: $(UTILSDIR)timeUtil.h $(UTILSDIR)timeUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^

ruleUtil.o: $(UTILSDIR)ruleUtil.h $(UTILSDIR)ruleUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^

flowUtil.o: $(UTILSDIR)flowUtil.h $(UTILSDIR)flowUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^

ipUtil.o: $(UTILSDIR)ipUtil.h $(UTILSDIR)ipUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^

memUtil.o: $(UTILSDIR)memUtil.h $(UTILSDIR)memUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^
	
mathUtil.o: $(UTILSDIR)mathUtil.h $(UTILSDIR)mathUtil.cpp
	$(CPP) $(CPPFLAGS) -c $^
	

.PHONY : clean
clean:
	rm -f *.gch *~ $(FHTDIR)*.gch $(FHTDIR)*~ $(OBJDIR)* $(RULESDIR)*.gch $(RULESDIR)*~ $(TESTDIR)*~ $(TSDIR)*.gch $(TSDIR)*~ $(UTILSDIR)*.gch $(UTILSDIR)*~ *.o $(APPNAME)

.PHONY : move_obj
move_obj:
	mv *.o $(OBJDIR) 

