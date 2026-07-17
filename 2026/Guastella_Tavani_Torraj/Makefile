CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -Iinclude

.PHONY: all mark-setup mark-status mark-clean mark-smoke clean

all: firewall

firewall: src/*.c include/*.h firewall.conf
	$(CC) $(CFLAGS) src/*.c -o $@ -lnetfilter_queue -lm

mark-setup:
	sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80 23

mark-status:
	sudo ./scripts/fw_mark_status.sh

mark-clean:
	sudo ./scripts/fw_mark_cleanup.sh

mark-smoke: firewall
	sudo ./scripts/fw_mark_smoke_test.sh

clean:
	rm -rf build firewall firewall.log
