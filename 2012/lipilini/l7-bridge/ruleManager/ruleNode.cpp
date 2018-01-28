#include <cstdio>
#include <cstdlib>

#include "ruleUtil.h"
#include "ruleNode.h"

ruleNode::ruleNode(){
	v4_rule = NULL;
	v6_rule = NULL;
	
	child_0 = NULL;
	child_1 = NULL;
}

ruleNode::~ruleNode(){
	if(child_0 != NULL){
		delete child_0;
		child_0 = NULL;
	}
		
	if(child_1 != NULL){
		delete child_1;
		child_1 = NULL;
	}
	
	//delete this;
}

void ruleNode::print_rule_node(){
	
	//
	// TODO : choose a way to print ruleNode !
	//
	
}
