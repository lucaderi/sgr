#include <new>
#include <cstdio>
#include <cstring>
#include <ctime>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libxml++/libxml++.h>

#include "ipUtil.h"
#include "ruleManager.h"

using namespace Glib;
using namespace std;
using namespace xmlpp;

ruleManager::ruleManager(char * _conf_file){
	rList = NULL;
	old_rList = NULL;
	
	trie = NULL;
	old_trie = NULL;

	conf_file = strdup(_conf_file);
  
  rule_version = 0;
  
  firstMake = true;
  maxQueueIndex = 0;
}

ruleManager::~ruleManager(){
	delete_oldies();
	
  if(trie != NULL){
		delete trie;
		trie = NULL;
	}
  
	if(rList != NULL){
		delete rList;
		rList = NULL;
	}
			
	free(conf_file);
	conf_file = NULL;
		
	//delete this
}

int ruleManager::make_rules(){
	int _id = 0;
	bool _allow;
  int e;
  bool b;
	
	ruleList * tmpList = NULL;
	ruleTrie * tmpTrie = NULL;
	
	bool v4_def_allow;
	bool v6_def_allow;
	splitted_ip_t sip;
	ruleStruct * _rS;

	Node * pNode;
	Node::NodeList::iterator iter;
	Node::NodeList nodeList;
	Element * nodeElem;
	Attribute * nodeAttr;
	ustring nodeName;
  
	DomParser parser;
	parser.set_substitute_entities();
	parser.parse_file(conf_file);
  
	if(!parser)
		return -1;
	
  if(unlikely(firstMake)){
    nodeList = parser.get_document()->get_root_node()->get_children("queueSet");

    if(nodeList.size() != 1)
      return -1;

    pNode = nodeList.front();
    nodeElem = dynamic_cast<Element*>(pNode);
    nodeAttr = nodeElem->get_attribute("masterQueueNumber");
    if(!nodeAttr)
      return -1;

    maxQueueIndex = atoi(nodeAttr->get_value().c_str()) - 1;

    firstMake = false;
  }
  
  nodeList = parser.get_document()->get_root_node()->get_children("ruleSet");

  if(nodeList.size() != 1)
    return -1;
  
  pNode = nodeList.front();
  
	nodeElem = dynamic_cast<Element*>(pNode);
	
	nodeAttr = nodeElem->get_attribute("default_v4_rule");
	if(!nodeAttr)
		return -1;
		
	if(strcmp(nodeAttr->get_value().c_str(), "ALLOW") == 0){
		v4_def_allow = true;
	}else{
		v4_def_allow = false;
	}
		
	nodeAttr = nodeElem->get_attribute("default_v6_rule");
	if(!nodeAttr)
		return -1;
		
	if(strcmp(nodeAttr->get_value().c_str(), "ALLOW") == 0){
		v6_def_allow = true;
	}else{
		v6_def_allow = false;
	}
	
	tmpList = new ruleList();
	
	tmpTrie = new ruleTrie(v4_def_allow, v6_def_allow);

	nodeList = pNode->get_children();
  for(iter = nodeList.begin(); iter != nodeList.end(); ++iter){
		pNode = * iter;
		nodeElem = dynamic_cast<Element*>(pNode);
		nodeName = pNode->get_name();
		
		if(strcmp(nodeName.c_str(), "rule") == 0){
			nodeAttr = nodeElem->get_attribute("id");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of rule invalid ! Attribute 'id' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			_id = atoi(nodeAttr->get_value().c_str());
			
      _rS = tmpList->find_list_rule(_id);
      if(_rS != NULL){
        printf("[ ruleManager ] Rule ID already in use ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
      }
      
			nodeAttr = nodeElem->get_attribute("action");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of rule invalid ! Attribute 'action' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			if(strcmp(nodeAttr->get_value().c_str(), "ALLOW") == 0){
				_allow = true;
			}else{
				_allow = false;
			}
			
			nodeAttr = nodeElem->get_attribute("protocol");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of rule invalid ! Attribute 'protocol' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}

      b = tmpList->add_list_rule(_id, _allow, nodeAttr->get_value().c_str(), maxQueueIndex);
      if(b)
        printf("[ ruleManager ] Rule added with queue index error ! (line %d)\n", nodeElem->get_line());
		}
		
		else if(strcmp(nodeName.c_str(), "match_v4") == 0){
			nodeAttr = nodeElem->get_attribute("rule_id");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of match_v4 invalid ! Attribute 'rule_id' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			_id = atoi(nodeAttr->get_value().c_str());
			
			_rS = tmpList->find_list_rule(_id);
			if(_rS == NULL){
				printf("[ ruleManager ] Invalid rule_id in match_v4 ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			
			nodeAttr = nodeElem->get_attribute("ip");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of match_v4 invalid ! Attribute 'ip' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			e = split_ipv4(&sip, nodeAttr->get_value().c_str());
			
      if(e < 0){
        printf("[ ruleManager ] Format of match_v4 invalid ! Attribute 'ip' malformed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
      }
      
			tmpTrie->set_trie_rule(4, &(sip.ip), sip.mask, _rS);
		}
		
		else if(strcmp(nodeName.c_str(), "match_v6") == 0){
			nodeAttr = nodeElem->get_attribute("rule_id");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of match_v6 invalid ! Attribute 'rule_id' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			_id = atoi(nodeAttr->get_value().c_str());
			
			_rS = tmpList->find_list_rule(_id);
			if(_rS == NULL){
				printf("[ ruleManager ] Invalid rule_id in match_v6 ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			
			nodeAttr = nodeElem->get_attribute("ip");
			if(!nodeAttr){
				printf("[ ruleManager ] Format of match_v6 invalid ! Attribute 'ip' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			e = split_ipv6(&sip, nodeAttr->get_value().c_str());
			
      if(e < 0){
        printf("[ ruleManager ] Format of match_v6 invalid ! Attribute 'ip' malformed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
      }
      
			tmpTrie->set_trie_rule(6, &(sip.ip), sip.mask, _rS);
		}
		
		else{
			//printf("FIND %s (possibly indentation !)\n", nodeName.c_str());
		}
		
  }
  
  rList = tmpList;
  trie = tmpTrie;
  
	return 0;
}

int ruleManager::update_rule(){
	int e = 0;
	
	if(old_rList != NULL || old_trie != NULL){
		return UPDATE_TIME_ERROR;
	}
	
	old_rList = rList;
	old_trie = trie;
	
	e = make_rules();
	if(e < 0){
		old_rList = NULL;
		old_trie = NULL;
		
		return UPDATE_MAKE_ERROR;
	}
	
	// update rule version !
  rule_version++;
		
	return 0;
}

void ruleManager::delete_oldies(){
	if(old_trie != NULL){
		delete old_trie;
		old_trie = NULL;
	}
  
  if(old_rList != NULL){
		delete old_rList;
		old_rList = NULL;
	}
	
	return;
}
