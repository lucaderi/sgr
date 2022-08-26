# tool macros
CC := gcc
LIBNDPI := /usr/local# path to libndpi
INCLUDE := -I${LIBNDPI}/include/ndpi  
CCFLAGS := -O2 $(INCLUDE) -Wno-implicit-function-declaration
CCOBJFLAGS := $(CCFLAGS) -c
LIBS := -L${LIBNDPI}/lib -lndpi -lrrd -lm

# path macros
BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src

# compile macros
TARGET_NAME := pcount
TARGET := $(BIN_PATH)/$(TARGET_NAME)

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# non-phony targets
$(TARGET): $(OBJ) | $(BIN_PATH)
	$(CC) -o $@ $(OBJ) $(CCFLAGS) $(LIBS)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c* | $(OBJ_PATH)
	$(CC) $(CCOBJFLAGS) -o $@ $<

$(BIN_PATH):
	mkdir -p $(BIN_PATH)

$(OBJ_PATH):
	mkdir -p $(OBJ_PATH)
	
# phony rules
.PHONY: all clean cleanall

all: $(TARGET)

clean:
	rm -f monitor.rrd graph.png
cleanall:
	rm -rf $(TARGET) $(BIN_PATH) $(OBJ_PATH) monitor.rrd graph.png