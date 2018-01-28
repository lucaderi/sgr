#include <cstdio>

#include "ruleTrie.h"
#include "ipUtil.h"

ruleTrie::ruleTrie(bool _v4_default_allow, bool _v6_default_allow){
	root = new ruleNode();
	
	if(_v4_default_allow)
		v4_default.type = ALLOW_ALL;
	else
		v4_default.type = DENY_ALL;
	
	
	if(_v6_default_allow)
		v6_default.type = ALLOW_ALL;
	else
		v6_default.type = DENY_ALL;

}

ruleTrie::~ruleTrie(){
	delete root;
	root = NULL;
	
	//delete this;
}

ruleNode * ruleTrie::find_prefix_rule_node(u_int8_t _ip_version, ip_addr * _ip){
	ruleNode * last_valid = NULL;
	ruleNode * curr = root;
	int i = 31;
  int j = 3;
	
	if(_ip_version == 4){
    // IPv4 algorithm
		while(curr != NULL && i >= 0){
			if(curr->have_valid_rule(_ip_version))
				last_valid = curr;
			
			if(is_set_bit(_ip->v4, i)){
				curr = curr->get_child_1();
			}else{
				curr = curr->get_child_0();
			}
			i--;
		}
	}else{
    // IPv6 algorithm
		while(curr != NULL && j >= 0){
			if(curr->have_valid_rule(_ip_version))
				last_valid = curr;

			if(is_set_bit(_ip->v6.__in6_u.__u6_addr32[j], i)){
				curr = curr->get_child_1();
			}else{
				curr = curr->get_child_0();
			}
			i--;
			if(i == -1){
				i = 7;
				j--;
			}
		}
	}
	
	if(curr!=NULL && curr->have_valid_rule(_ip_version))
		return curr;
	else
		return last_valid;
}

ruleNode * ruleTrie::add_rule_node(u_int8_t _ip_version, ip_addr * _ip, int net){
	ruleNode * p = NULL;
	ruleNode * curr = root;
	int i, j, lim;
	
	if(_ip_version == 4){
		for(i=31; i>=(32-net); i--){
			if(is_set_bit(_ip->v4, i)){
				if((p = curr->get_child_1()) == NULL){
					p = new ruleNode();
					curr->set_child_1(p);
				}
			}else{
				// bit i is 0
				if((p = curr->get_child_0()) == NULL){
					p = new ruleNode();
					curr->set_child_0(p);
				}
			}
			curr = p;
		}
	}else{
		for(j=3; j>=(net/32); j--){
			
			if(j!=net/32)
				lim = 0;
			else
				lim = net%32;
					
			for(i=31; i>=lim; i--){
				if(is_set_bit(_ip->v6.__in6_u.__u6_addr32[j], i)){
					if((p = curr->get_child_1()) == NULL){
						p = new ruleNode();
						curr->set_child_1(p);
					}
				}else{
					// bit i is 0
					if((p = curr->get_child_0()) == NULL){
						p = new ruleNode();
						curr->set_child_0(p);
					}
				}
				curr = p;
			}
		}
	}

	return curr;
}
