#ifndef _RULENODE_H_
#define _RULENODE_H_

#include "ipq_api.h"
#include "pfring.h"

#include "ruleStruct.h"

typedef struct rule_ret{
	rule_type_t type;
	rule_t rule;
}rule_ret_t;

class ruleNode
{
	public:
		ruleNode();
		~ruleNode();
		__inline__ bool have_valid_rule(u_int8_t _ip_version) { return ((_ip_version == 4) ? (v4_rule != NULL) : (v6_rule != NULL)); }
    __inline__ rule_ret_t get_v4_rule() { rule_ret_t r; r.type = v4_rule->get_type(); if(r.type == SPECIFIC_RULE){ r.rule = v4_rule->get_rule_copy(); } return r; }
    __inline__ rule_ret_t get_v6_rule() { rule_ret_t r; r.type = v6_rule->get_type(); if(r.type == SPECIFIC_RULE){ r.rule = v6_rule->get_rule_copy(); } return r; }
		__inline__ void set_rule(u_int8_t _ip_version, ruleStruct * _rS) { (_ip_version == 4) ? (v4_rule = _rS) : (v6_rule = _rS); }
		__inline__ ruleNode * get_child_0() { return child_0; }
		__inline__ void set_child_0(ruleNode * _rN) { child_0 = _rN; }
		__inline__ ruleNode * get_child_1() { return child_1; }
		__inline__ void set_child_1(ruleNode * _rN) { child_1 = _rN; }
		void print_rule_node();
				
	protected:
		
	private:
		ruleStruct * v4_rule;
		ruleStruct * v6_rule;
		ruleNode * child_0;
		ruleNode * child_1;	
};

#endif // _RULENODE_H_
