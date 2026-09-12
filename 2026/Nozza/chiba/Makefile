# Compiler and flags 
CC 	    := gcc
CFLAGS  := -Wall -Wextra -O2 -g -Iinclude
TARGET  := bin/chiba
# Link external libraries
LDFLAGS := -lcurl -lpthread

# Directories
SRC_DIR := src
OBJ_DIR := build
BIN_DIR := bin

# Find source files in src/ and object files in build/
SRCS    := $(wildcard $(SRC_DIR)/*.c)
OBJS    := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

SQL_DIR := sql

db-init:
	@for f in $(SQL_DIR)/*.sql; do \
		echo "[db-init] Applying $$f..."; \
		clickhouse-client -n --queries-file $$f || exit 1; \
	done

db-drop:
	@echo "[db-drop] WARNING: This will permanently destroy the 'chiba' database and all telemetry data."
	@read -p "Type 'yes' to confirm: " confirm && [ "$$confirm" = "yes" ] || exit 1
	@clickhouse-client --query "DROP DATABASE IF EXISTS chiba;"
	@echo "[db-drop] Database destroyed."

db-reset: db-drop db-init
	@echo "[db-reset] Database has been completely reset and initialized."

# Create directories before compilation
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf  $(OBJ_DIR) $(BIN_DIR)

.PHONY: clean db-init db-drop
