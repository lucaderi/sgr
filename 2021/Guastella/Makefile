
AR       = ar
ARFLAGS  = rvs

CC       = gcc


TARGETS   =    MainTest

.PHONY: cleanall

%: %.c
	@$(CC) -o $@ $<

%.o: %.c
	@$(CC) -c -o $@ $<

all: $(TARGETS)

MainTest: MainTest.o lib_count_min.a
	@$(CC) $^ -o $@

lib_count_min.a: lib/count_min_sketch.o lib/fun_hash.o
	@$(AR) $(ARFLAGS) $@ $^
test1:
	@valgrind --leak-check=full --track-origins=yes ./MainTest

test2:
	@valgrind --leak-check=full --track-origins=yes ./MainTest 1

cleanall :
	@rm -f *.txt *.a *.o lib/*.o lib/*.a
	@rm -f MainTest
	@rm -f testHash

