#include <cstdio>
#include <cstdlib>

#include "ruleList.h"

ruleList::ruleList(){
	head = NULL;
}

ruleList::~ruleList(){
	ruleStruct * p = head;
	ruleStruct * tmp;
	
	while(p!=NULL){
		tmp = p->get_next();
		
		delete p;
		
		p = tmp;
	}
	
	//delete this;
}

ruleStruct * ruleList::find_list_rule(int _id){
	ruleStruct * curr = head;
	
	while(curr!=NULL){
		if(curr->get_id() == _id){
			return curr;
		}
		
		curr = curr->get_next();
	}
	
	return NULL;
}
