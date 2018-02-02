#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>
#include <limits.h>
#include <arpa/inet.h>

#include "formats.h"
#include "libs/uthash/uthash.h"

// Called on termination to clean the envirnoment setted up by the analyzer
void cleanAnalyzer();
// Called each time a packet that respects the security policy is captured
void Analyze(int caplen, const uint8_t *bytes);

#endif
