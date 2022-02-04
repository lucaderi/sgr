#ifndef _IPOQUEUTIL_H
#define _IPOQUEUTIL_H

#include "ipq_api.h"
#include "pfring.h"

typedef struct rule{
  IPOQUE_PROTOCOL_BITMASK pB;
  int q[IPOQUE_MAX_SUPPORTED_PROTOCOLS];
  bool with_error;
}rule_t;

rule_t * plisttort(bool _allow, const char * _proto_list, u_int16_t _mqi);

#endif // _IPOQUEUTIL_H
