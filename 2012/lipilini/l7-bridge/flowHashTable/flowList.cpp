#include <cstdio>

#include "flowList.h"
#include "ipUtil.h"

#define DEFAULT_UNUSED_SEC_TIME 120

flowList::flowList(){
  activeFlowHead = NULL;
  lastActiveFlowPointer = NULL;
  firstUnusedFlowPointer = NULL;
}

flowList::~flowList(){
  flowStruct * p = activeFlowHead;
  flowStruct * tmp = NULL;

  while(p != NULL){
    tmp = p->get_next();
    delete p;
		p = tmp;
  }

	//delete this;
}

flowStruct * flowList::find_list_flow(flowKey_t * _key, timeval * _now){
  flowStruct * curr = activeFlowHead;
  flowStruct * prev = NULL;

  while(likely(curr != NULL)){
    // check for time gap
    if(unlikely((_now->tv_sec - curr->get_last_pkt_time()->tv_sec) > DEFAULT_UNUSED_SEC_TIME)){
      // the other flowStruct have greater time gap (>= DEFAULT_UNUSED_SEC_TIME)
      lastActiveFlowPointer = prev;
      firstUnusedFlowPointer = curr;
      break;
    }
    
    // check for equality
    if(curr->have_same_key(_key)){
      (likely(prev != NULL)) ? detach_from_list(prev, curr) : detach_from_head(curr);
      return curr;
    }
    
    prev = curr;
    curr = curr->get_next();
  }
  
  return NULL;
}

flowStruct * flowList::pick_from_unused_flow(){
  flowStruct * p = firstUnusedFlowPointer;
    
  firstUnusedFlowPointer = firstUnusedFlowPointer->get_next();
    
  (likely(lastActiveFlowPointer != NULL)) ? detach_from_list(lastActiveFlowPointer, p) : detach_from_head(p);
  
  return p;
}

u_int32_t flowList::remove_deletable_list_flow(){
	u_int32_t deleted = 0;
	flowStruct * curr = NULL;
  
  if(firstUnusedFlowPointer == NULL)
    return 0;
  
  while((curr = pick_from_unused_flow()) != NULL){
    delete curr;
    deleted++;
  }
  
	return deleted;
}

void flowList::print_flow_list(timeval * _now){
  flowStruct * p = activeFlowHead;

  if(p == NULL){
    printf("( EMPTY LIST )\n");
    return;
  }

  printf("( BEGIN LIST ...\n\n");
  while(p != NULL){
    p->print_flow_struct(_now);
    p = p->get_next();
  }
  printf("... END LIST )\n");

  return;
}
