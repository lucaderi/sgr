#ifndef _RULETRIE_H_
#define _RULETRIE_H_

#include "ipq_api.h"
#include "pfring.h"

#include "ruleStruct.h"
#include "ruleNode.h"

class ruleTrie
{
	public:
		ruleTrie(bool _v4_default_allow, bool _v6_default_allow);
		~ruleTrie();
    
		__inline__ rule_ret_t get_trie_rule(u_int8_t _ip_version, ip_addr * _ip)
        { ruleNode * rN = find_prefix_rule_node(_ip_version, _ip); return ( (rN != NULL) ? get_node_rule(_ip_version, rN) : get_default_rule(_ip_version) ); }
    
		__inline__ void set_trie_rule(u_int8_t _ip_version, ip_addr * _ip, int _net, ruleStruct * _rS)
        { ruleNode * rN = add_rule_node(_ip_version, _ip, _net); rN->set_rule(_ip_version, _rS); }
				
	protected:
    __inline__ rule_ret_t get_node_rule(u_int8_t _ip_version, ruleNode * _rN) { return ( (_ip_version == 4) ? _rN->get_v4_rule() : _rN->get_v6_rule() ); }
		__inline__ rule_ret_t get_default_rule(u_int8_t _ip_version) { return ( (_ip_version == 4) ? v4_default : v6_default ); }
    ruleNode * find_prefix_rule_node(u_int8_t _ip_version, ip_addr * _ip);
		ruleNode * add_rule_node(u_int8_t _ip_version, ip_addr * _ip, int net);
		
	private:
		ruleNode * root;
		rule_ret_t v4_default;
		rule_ret_t v6_default;
};

#endif // _RULETRIE_H_
