SRC= Test_find_strings.c Find_strings.c

CFLAGS=-Wall -pedantic
CC=gcc 
LIBS= -lm

PROGRAM_NAME=find_strings

.PHONY = clean

$(PROGRAM_NAME): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(PROGRAM_NAME) $(SRC) $(LIBS)
	
clean: 
	rm -f find_strings
