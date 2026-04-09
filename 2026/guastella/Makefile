CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

TARGET = pbridge
SRC = pbridge_1.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)