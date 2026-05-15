CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -Iinclude

.PHONY: all test mark-setup mark-status mark-clean mark-smoke clean

all: firewall

firewall: src/*.c include/*.h firewall.conf
	$(CC) $(CFLAGS) src/*.c -o $@ -lnetfilter_queue -lm

build:
	mkdir -p build

build/main_for_test.o: src/main.c include/*.h | build
	$(CC) $(CFLAGS) -Dmain=firewall_main -c src/main.c -o $@

build/test_firewall: tests/test_firewall.c build/main_for_test.o src/parser.c src/decision.c src/hyperloglog.c src/rate_limit.c src/rules.c include/*.h firewall.conf | build
	$(CC) $(CFLAGS) tests/test_firewall.c build/main_for_test.o src/parser.c src/decision.c src/hyperloglog.c src/rate_limit.c src/rules.c -o $@ -lm

test: build/test_firewall
	./build/test_firewall

mark-setup:
	sudo ./scripts/fw_mark_setup.sh

mark-status:
	sudo ./scripts/fw_mark_status.sh

mark-clean:
	sudo ./scripts/fw_mark_cleanup.sh

mark-smoke: firewall
	sudo ./scripts/fw_mark_smoke_test.sh

clean:
	rm -rf build firewall firewall.log
