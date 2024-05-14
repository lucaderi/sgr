# Compilatore
CC = gcc
# Opzioni di compilazione
CFLAGS = -g

# Directory contenente i file di libreria
LIB_DIR_1 = Radiotap_LIB
LIB_DIR_2 = MyHash_Lib

# Librerie da linkare
LIBS = -lpcap

# Nome dell'eseguibile finale
TARGET = AirWatch_v1

.PHONY: all clean test1 test2 test3 test4

all: $(TARGET)

# Compilazione del programma
$(TARGET): airwatch_v1.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_DIR_1)/radiotap.c $(LIB_DIR_2)/myhash_lib.c $(LIBS)

clean:
	rm -f $(TARGET)

test1: $(TARGET)
	@echo "Running AirWatch - Offline Capture | Verbose 2"
	@sudo ./$(TARGET) -i test/test1.pcap -v 2

test2: $(TARGET)
	@echo "Running AirWatch - Offline Capture | Verbose 1"
	@sudo ./$(TARGET) -i test/test2.pcap -v 2

test3: $(TARGET)
	@echo "Running AirWatch - Offline Capture | Verbose 2"
	@sudo ./$(TARGET) -i test/test3.pcap -v 1

test4: $(TARGET)
	@echo "Running AirWatch - Offline Capture | Verbose 1"
	@sudo ./$(TARGET) -i test/test4.pcap -v 1