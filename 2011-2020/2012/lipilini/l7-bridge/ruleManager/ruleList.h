#ifndef _RULELIST_H_
#define _RULELIST_H_

#include "ruleStruct.h"

class ruleList
{
	public:
		ruleList();
		~ruleList();
    
		__inline__ bool add_list_rule(int _id, bool _allow, const char * _proto_list, u_int16_t _mqi)
        { ruleStruct * p = new ruleStruct(_id, _allow, _proto_list, head, _mqi); head = p; return p->have_error(); }
		
    ruleStruct * find_list_rule(int _id);
				
	protected:
		
	private:
		ruleStruct * head;
};

#endif // _RULELIST_H_
