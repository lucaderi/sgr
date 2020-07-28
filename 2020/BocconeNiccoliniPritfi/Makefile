# Makefile
CC	=  gcc
CFLAGS	= -Wall -g
LDFLAGS = -L ./lib
obj = ./src/main.c ./lib/libbt.so
TARGET = ./bin/myprog

.PHONY: all test2 clean

./bin/myprog : $(obj)
	$(CC) -lpcap $(CFLAGS) $^ -I ./include -o $@ $(LDFLAGS) -lbt

./lib/libbt.so : ./src/jitter_data.o ./src/time_tools.o
	$(CC) $(CFLAGS) -shared -o $@ $^

./src/jitter_data.o : ./src/jitter_data.c
	$(CC) $(CFLAGS) $< -I ./include -fPIC -c -o $@

./src/time_tools.o : ./src/time_tools.c
	$(CC) $(CFLAGS) $< -I ./include -fPIC -c -o $@

all: $(TARGET)

test1:	./bin/myprog
	@echo "Eseguo il test1, catturo 50 pacchetti"
	sudo ./bin/myprog 50
	@echo "Test1 OK"

# valgrind --track-origins=yes
# valgrind --leak-check=full
test2:	./bin/myprog
	@echo "Eseguo il test2, mandare SIGINT per interrompere"
	sudo ./bin/myprog
	@echo "Test2 OK"

clean:
	@echo "Removing garbage"
	-rm -f ./bin/myprog
	-rm -d -r -f ./bin/*.dSYM ./lib/*.dSYM
	-rm -f ./src/*.o ./lib/libbt.so
