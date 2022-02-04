#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "ruleUtil.h"

unsigned int pstrtopui(char * _proto){
	static const char * protocol_str[] = { IPOQUE_PROTOCOL_SHORT_STRING };
	unsigned int i;
	
	for(i=0; i<IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++){
		if(strcmp(_proto, protocol_str[i]) == 0)
			return i;
	}
	
	return 0;
}

typedef struct s_split{
  char * proto;
  char * queue;
}s_split_t;

__inline__ s_split_t separatePQ(char * _s){
  s_split_t ss;
  ss.proto = strtok(_s, "@");
  ss.queue = strtok(NULL, "");
  return ss;
}

rule_t * plisttort(bool _allow, const char * _proto_list, u_int16_t _mqi){
  rule_t * r = (rule_t *)calloc(1, sizeof(rule_t));
  r->with_error = false;
	IPOQUE_PROTOCOL_BITMASK pB;
  int q[IPOQUE_MAX_SUPPORTED_PROTOCOLS];
  int i;
  unsigned int pui;
  int pll, l = 0;
	char * pL = strdup(_proto_list);
	char _s[32] = { 0 };
  s_split_t _ss = { NULL, NULL };
  
  // initialize variables
	if(_allow){
		IPOQUE_BITMASK_RESET(pB);
	}else{
		IPOQUE_BITMASK_SET_ALL(pB);
	}
  
  for(i=0; i<IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++){
    q[i] = -1;
  }
	
  // analyze protocol list
  pll = strlen(_proto_list);
  
  while(l <= pll){
    sscanf(pL+l, "%s", _s);
    
    l += strlen(_s) + 1;
    
    _ss = separatePQ(_s);
    
    pui = pstrtopui(_ss.proto);
    if(_allow){
			IPOQUE_ADD_PROTOCOL_TO_BITMASK(pB, pui);
      if(_ss.queue != NULL){
        q[pui] = atoi(_ss.queue);
        if(q[pui] > _mqi){
          IPOQUE_DEL_PROTOCOL_FROM_BITMASK(pB, pui);
          q[pui] = -1;
          r->with_error = true;
        }
      }
		}else{
			IPOQUE_DEL_PROTOCOL_FROM_BITMASK(pB, pui);
		}
    
  }
  
  free(pL);
  
  IPOQUE_BITMASK_SET(r->pB, pB);
  memcpy(&(r->q), &q, sizeof(int) * IPOQUE_MAX_SUPPORTED_PROTOCOLS);
  
  return r;
}
