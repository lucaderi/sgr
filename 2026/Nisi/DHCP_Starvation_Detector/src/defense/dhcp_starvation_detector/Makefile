CC      = gcc
CFLAGS  = -Wall -Wextra -std=gnu99 -O2
LDFLAGS = -lpcap

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(abspath $(MAKEFILE_DIR)/../../..)
BINDIR ?= $(PROJECT_ROOT)/bin

# libnetconf2 changed the client SSH known-hosts API across versions.
# Compile a tiny probe to detect which API is available, then define the
# matching macro so netconf_action.c can build on both old and new systems.
NETCONF_KNOWNHOSTS_CFLAGS := $(shell \
	printf '\043include <nc_client.h>\nint main\050void\051 { nc_client_ssh_set_knownhosts_mode\050NC_SSH_KNOWNHOSTS_ACCEPT_NEW\051; return 0; }\n' | \
	$(CC) -Wall -Werror=implicit-function-declaration -std=gnu99 -x c -c -o /dev/null - >/dev/null 2>&1 && \
	echo -DHAVE_NC_KNOWNHOSTS_MODE || \
	echo -DHAVE_NC_AUTH_HOSTKEY_CHECK_CLB)
CFLAGS += $(NETCONF_KNOWNHOSTS_CFLAGS)

TEST_PARSER     = $(BINDIR)/test_parser
TEST_WL         = $(BINDIR)/test_whitelist
TEST_NETCONF    = $(BINDIR)/test_netconf_action
TEST_DETECTOR   = $(BINDIR)/test_detector
TEST_REPUTATION = $(BINDIR)/test_reputation
DEFENSE_MAIN    = $(BINDIR)/dhcp_starvation_detector

PARSER_OBJ     = $(BINDIR)/dhcp_parser.o
CONFIG_OBJ     = $(BINDIR)/defense_config.o
WL_OBJ         = $(BINDIR)/whitelist.o
NETCONF_OBJ    = $(BINDIR)/netconf_action.o
NETCONF_WORKER_OBJ = $(BINDIR)/netconf_worker.o
NETCONF_DISABLED_OBJ = $(BINDIR)/netconf_disabled.o
REPUTATION_OBJ = $(BINDIR)/mac_reputation.o
RRD_OBJ        = $(BINDIR)/rrd_stats.o
DETECTOR_OBJS  = $(BINDIR)/detector.o       \
                 $(BINDIR)/sliding_window.o \
                 $(BINDIR)/leaky_bucket.o   \
                 $(BINDIR)/adaptive_score.o
LEGACY_OBJ_FILES = $(MAKEFILE_DIR)/dhcp_parser/*.o     \
                   $(MAKEFILE_DIR)/detector/*.o        \
                   $(MAKEFILE_DIR)/netconf_action/*.o  \
                   $(MAKEFILE_DIR)/reputation/*.o      \
                   $(MAKEFILE_DIR)/rrd/*.o             \
                   $(MAKEFILE_DIR)/whitelist/*.o
LEGACY_BIN_DIR = $(MAKEFILE_DIR)/bin
NETCONF_ENABLED_STAMP = $(BINDIR)/.netconf_enabled

.PHONY: all no-netconf clean

all: $(TEST_PARSER) $(TEST_WL) $(TEST_NETCONF) $(TEST_DETECTOR) $(TEST_REPUTATION) $(DEFENSE_MAIN)

no-netconf: $(TEST_PARSER) $(TEST_WL) $(TEST_REPUTATION) \
     $(DETECTOR_OBJS) $(RRD_OBJ) \
     $(BINDIR)/test_detector.o $(BINDIR)/dhcp_starvation_detector.o \
     $(NETCONF_DISABLED_OBJ) $(WL_OBJ)
	$(CC) $(CFLAGS) -o $(TEST_DETECTOR) \
	    $(BINDIR)/test_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) \
	    $(PARSER_OBJ) $(NETCONF_DISABLED_OBJ) $(CONFIG_OBJ) \
	    $(LDFLAGS) -lm
	$(CC) $(CFLAGS) -o $(DEFENSE_MAIN) \
	    $(BINDIR)/dhcp_starvation_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) \
	    $(PARSER_OBJ) $(NETCONF_DISABLED_OBJ) $(WL_OBJ) \
	    $(REPUTATION_OBJ) $(CONFIG_OBJ) $(LDFLAGS) -lm
	rm -f $(NETCONF_ENABLED_STAMP)

$(TEST_PARSER): $(BINDIR)/test_parser.o $(PARSER_OBJ) $(CONFIG_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_WL): $(BINDIR)/test_whitelist.o $(WL_OBJ) $(CONFIG_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_NETCONF): $(BINDIR)/test_netconf_action.o $(NETCONF_OBJ) $(WL_OBJ) $(CONFIG_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lnetconf2 -lyang

$(NETCONF_ENABLED_STAMP):
	@mkdir -p $(BINDIR)
	@printf 'enabled\n' > $@

$(TEST_DETECTOR): $(BINDIR)/test_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) $(PARSER_OBJ) $(NETCONF_OBJ) $(CONFIG_OBJ) $(NETCONF_ENABLED_STAMP)
	$(CC) $(CFLAGS) -o $@ \
	    $(BINDIR)/test_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) \
	    $(PARSER_OBJ) $(NETCONF_OBJ) $(CONFIG_OBJ) \
	    $(LDFLAGS) -lm -lnetconf2 -lyang

$(TEST_REPUTATION): $(BINDIR)/test_reputation.o $(REPUTATION_OBJ) $(WL_OBJ) $(PARSER_OBJ) $(CONFIG_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lm

$(DEFENSE_MAIN): $(BINDIR)/dhcp_starvation_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) $(PARSER_OBJ) $(NETCONF_OBJ) $(NETCONF_WORKER_OBJ) $(WL_OBJ) $(REPUTATION_OBJ) $(CONFIG_OBJ) $(NETCONF_ENABLED_STAMP)
	$(CC) $(CFLAGS) -o $@ \
	    $(BINDIR)/dhcp_starvation_detector.o $(DETECTOR_OBJS) $(RRD_OBJ) \
	    $(PARSER_OBJ) $(NETCONF_OBJ) $(NETCONF_WORKER_OBJ) $(WL_OBJ) \
	    $(REPUTATION_OBJ) $(CONFIG_OBJ) $(LDFLAGS) -lm -lnetconf2 -lyang \
	    -lpthread

$(BINDIR)/test_parser.o:                dhcp_parser/test_parser.c            dhcp_parser/dhcp_parser.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/dhcp_parser.o:                dhcp_parser/dhcp_parser.c            dhcp_parser/dhcp_parser.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/defense_config.o:             config/defense_config.c              config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/test_whitelist.o:             whitelist/test_whitelist.c           whitelist/whitelist.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/whitelist.o:                  whitelist/whitelist.c                whitelist/whitelist.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/netconf_action.o:             netconf_action/netconf_action.c      netconf_action/netconf_action.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/netconf_worker.o:             netconf_action/netconf_worker.c      netconf_action/netconf_worker.h \
                                        netconf_action/netconf_action.h      whitelist/whitelist.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/netconf_disabled.o:           netconf_action/netconf_disabled.c    netconf_action/netconf_action.h \
                                        netconf_action/netconf_worker.h      whitelist/whitelist.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/test_netconf_action.o:        netconf_action/test_netconf_action.c netconf_action/netconf_action.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/sliding_window.o:             detector/sliding_window.c            detector/sliding_window.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/leaky_bucket.o:               detector/leaky_bucket.c              detector/leaky_bucket.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/adaptive_score.o:             detector/adaptive_score.c            detector/adaptive_score.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/rrd_stats.o:                  rrd/rrd_stats.c                      rrd/rrd_stats.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/detector.o:                   detector/detector.c                  detector/detector.h \
                                        detector/sliding_window.h            detector/leaky_bucket.h \
                                        detector/adaptive_score.h            rrd/rrd_stats.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/mac_reputation.o:             reputation/mac_reputation.c          reputation/mac_reputation.h \
                                        whitelist/whitelist.h                config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/test_reputation.o:            reputation/test_reputation.c         reputation/mac_reputation.h \
                                        dhcp_parser/dhcp_parser.h            config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/test_detector.o:              detector/test_detector.c             detector/detector.h \
                                        dhcp_parser/dhcp_parser.h            netconf_action/netconf_action.h \
                                        config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR)/dhcp_starvation_detector.o:   dhcp_starvation_detector.c           detector/detector.h \
                                        dhcp_parser/dhcp_parser.h            netconf_action/netconf_action.h \
                                        netconf_action/netconf_worker.h      reputation/mac_reputation.h \
                                        whitelist/whitelist.h                config/defense_config.h
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINDIR)/*.o \
	      $(TEST_PARSER) $(TEST_WL) $(TEST_NETCONF) $(TEST_DETECTOR) \
	      $(TEST_REPUTATION) $(DEFENSE_MAIN) $(NETCONF_ENABLED_STAMP)
	rm -f $(LEGACY_OBJ_FILES)
	rm -rf $(LEGACY_BIN_DIR)
