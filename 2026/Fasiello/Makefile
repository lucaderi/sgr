CC = gcc
# modify O0 -g to O3 in production
CFLAGS = -D_DEFAULT_SOURCE -fvisibility=hidden -Wall -Wextra -O0 -g -Iinclude
PKG_CFLAGS = $(shell pkg-config --cflags glib-2.0 libpcap libndpi librrd 2>/dev/null)
PKG_LIBS = $(shell pkg-config --libs glib-2.0 libpcap libndpi librrd 2>/dev/null)

CFLAGS += $(PKG_CFLAGS)
LDFLAGS = $(PKG_LIBS) -lm

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/netflow_analyzer

.PHONY: all clean directories install test

all: directories $(TARGET)

directories:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)

test: all
	./tests/run_tests.sh
