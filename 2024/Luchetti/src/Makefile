CC = gcc
CFLAGS = -Wall
LIBS = -lpcap
TARGET = vad
SRC = vad.c

# Regola principale: compila e esegui
all: $(TARGET)
	./$(TARGET)

# Regola per compilare il target
$(TARGET): $(SRC) Makefile
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

# Regola per pulire i file generati
clean:
	rm -f $(TARGET)
