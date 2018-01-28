#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "ruleUtil.h"
#include "ruleStruct.h"

ruleStruct::ruleStruct(int _id, bool _allow, const char * _proto_list, ruleStruct * _next, u_int16_t _mqi){
	id = _id;
	
  if(strcmp(_proto_list, "ALL") == 0){
    type = (_allow) ? ALLOW_ALL : DENY_ALL ;
    rule = NULL;
  }else{
    type = SPECIFIC_RULE;
    rule = plisttort(_allow, _proto_list, _mqi);
  }
	
	next = _next;
}

ruleStruct::~ruleStruct(){
	if(rule!=NULL){
    free(rule);
  }
		
	//delete this;
}