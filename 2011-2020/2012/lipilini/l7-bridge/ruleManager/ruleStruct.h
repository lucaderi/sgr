#ifndef _RULESTRUCT_H_
#define _RULESTRUCT_H_

#include "ruleUtil.h"

typedef enum rule_type{
	DENY_ALL = 0,
	ALLOW_ALL,
	SPECIFIC_RULE
}rule_type_t;

class ruleStruct
{
	public:
		ruleStruct(int _id, bool _allow, const char * _proto_list, ruleStruct * _next, u_int16_t _mqi);
		~ruleStruct();
		__inline__ int get_id() { return id; }
		__inline__ rule_type_t get_type() { return type; }
		__inline__ rule_t get_rule_copy() { return *rule; }
		__inline__ ruleStruct * get_next() { return next; }
    __inline__ bool have_error() { return ( (rule != NULL) ? rule->with_error : false ); }
				
	protected:
		
	private:
		int id;
		rule_type_t type;
		rule_t * rule;
		ruleStruct * next;
};

#endif // _RULESTRUCT_H_
