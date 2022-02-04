C = gcc
CFLAGS += -std=c99 -Wall -pedantic -D_DEFAULT_SOURCE -g
INCLUDES = -I./src
LDFLAGS = -lsnmp
OPTFLAGS = #-O3

SRC = src
OUT = out

OBJECT_FILES = \
	$(OUT)/log.o \
	$(OUT)/main.o

all: snmpscan

snmpscan: $(OBJECT_FILES)
	@mkdir -p $(OUT)
	$(C) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $(OUT)/$@ $(OBJECT_FILES) $(LDFLAGS)

$(OUT)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(C) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $<

test: snmpscan
	./test.sh

clean:
	rm -rf $(OUT)

doc:
	pdflatex -output-directory doc doc/snmpscan.tex

.PHONY: all snmpscan clean test doc