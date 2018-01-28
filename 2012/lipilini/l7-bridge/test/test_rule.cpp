#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipUtil.h"
#include "ruleUtil.h"
#include "ruleManager.h"
#include "pfring.h"

#include "ipq_api.h"

int main(int argc, char *argv[]){
	int i, e;
	char c;
	static const char * protocol_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };
	
  splitted_ip_t sip;
	ruleManager * rM;
	char * conf_file = NULL;
	char * ip = NULL;
	
	rule_ret_t rr;
  
  while((c = getopt(argc,argv,"c:i:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
			case 'c':
				conf_file = strdup(optarg);
				break;
			case 'i':
				ip = strdup(optarg);
				break;
    }
  }
  
  setbuf(stdout, NULL);
  
  if(conf_file == NULL){
		printf("Select a configuration file !\n");
		return -1;
	}
	if(ip == NULL){
		printf("Select a ip !\n");
		return -1;
	}
	
	rM = new ruleManager(conf_file);
  e = rM->update_rule();
	if(e < 0){
		printf("Error while parsing rule file !\n");
    return -1;
	}
	
	e = split_ipv4(&sip, ip);
  
  if(e < 0){
    printf("Error IP format !\n");
    return -1;
  }
	
	rr = rM->retrieve_rule(4, &(sip.ip));
	
	printf("Type : %d\n", rr.type);
	
	if(rr.type == SPECIFIC_RULE){
		printf("Protocol allowed :\n");
		for(i=0; i<IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++){
			if(IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(rr.rule.pB, i) != 0){
				printf("\t%s @ %d \n", protocol_long_str[i], rr.rule.q[i]);
			}	
		}
		printf("\n");
	}
	
	rM->update_rule();
	printf("\nAfter update ...\n\n");
	
	rr = rM->retrieve_rule(4, &(sip.ip));
	
	printf("Type : %d\n", rr.type);
	
	if(rr.type == SPECIFIC_RULE){
		printf("Protocol allowed :\n");
		for(i=0; i<IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++){
			if(IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(rr.rule.pB, i) != 0){
				printf("\t%s @ %d \n", protocol_long_str[i], rr.rule.q[i]);
			}	
		}
		printf("\n");
	}
	
	
	delete rM;
	free(conf_file);
	
	free(ip);
	
	return 0;
}
