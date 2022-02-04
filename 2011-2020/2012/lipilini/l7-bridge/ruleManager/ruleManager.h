#ifndef _RULEMANAGER_H_
#define _RULEMANAGER_H_

#include "ipq_api.h"
#include "pfring.h"

#include "ruleList.h"
#include "ruleTrie.h"

#define UPDATE_TIME_ERROR -1
#define UPDATE_MAKE_ERROR -2

class ruleManager
{	
	public:
		ruleManager(char * _conf_file);
		~ruleManager();
		__inline__ u_int32_t get_rule_version() { return rule_version;  }
		__inline__ rule_ret_t retrieve_rule(int _ip_version, ip_addr * _ip) { return trie->get_trie_rule(_ip_version, _ip); }
		int update_rule();
		void delete_oldies();
				
	protected:
		int make_rules();
		
	private:
		ruleList * rList;
		ruleList * old_rList;
		ruleTrie * trie;
		ruleTrie * old_trie;
		char * conf_file;
    u_int32_t rule_version;
    bool firstMake;
    u_int16_t maxQueueIndex;
};

#endif // _RULEMANAGER_H_
