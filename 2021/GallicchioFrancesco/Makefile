CC = gcc
CFLAGS = -std=c99 -I ./include

objects = ./roaring.o ./ip_dest_hash_table.o ./ip_dest.o

.PHONY: cleanall

./ip_dest: $(objects)
	$(CC) $(CFLAGS) -lpcap $^ -o $@
./ip_dest.o: ./src/ip_dest.c ./include/ip_dest_hash_table.h ./include/roaring.h
	$(CC) $(CFLAGS) $< -c -o $@
./ip_dest_hash_table.o: ./src/ip_dest_hash_table.c ./include/ip_dest_hash_table.h
	$(CC) $(CFLAGS) $< -c -o $@
./roaring.o: ./src/roaring.c ./include/roaring.h
	$(CC) $(CFLAGS) $< -c -o $@

cleanall:
	rm $(objects) ./ip_dest
	
