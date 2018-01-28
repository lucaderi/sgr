#include <cstdio>
#include <cstring>

#include "flowHashTable.h"
#include "mathUtil.h"

flowHashTable::flowHashTable(u_int32_t _size){
  u_int32_t i = 0;
  
  size = roundup_to_2_power(_size);
  sizeMask = size - 1;
  
  table = new flowList * [size];
  for(i=0; i<size; i++){
		table[i] = new flowList();
  }
	
  flowNum = 0;
  maxFlowNum = 3 * size;
  limFlowNum = 2 * size;
  listToUpdate = 0;
  listUpdateLim = size / 10;
}
    
flowHashTable::~flowHashTable(){
	u_int32_t i = 0;

  for(i=0; i<size; i++){
		delete table[i];
  }

  delete[] table;
  table = NULL;
  
  //delete this;
}

flowStruct * flowHashTable::add_new_capt_pkt(flowKey_t * _key, bool _upper_is_src, u_int64_t _n_bytes, timeval * _pkt_ts, timeval * _now){
  u_int32_t h = (likely(_key->ip_version == 4)) ? hash4(_key) : hash6(_key);
	flowStruct * pFS = table[h]->find_list_flow(_key, _now);
		
  if(pFS != NULL){
    return table[h]->update_list_flow(pFS, _upper_is_src, _n_bytes, _pkt_ts);
  }
  
  if(table[h]->have_unused_flow()){
    pFS = table[h]->pick_from_unused_flow();

    return table[h]->reuse_list_flow(pFS, _key, _upper_is_src, _n_bytes, _pkt_ts);
  }
  
  if(flowNum == maxFlowNum){
    return NULL;
  }
  
  flowNum++;
  
	return table[h]->add_new_list_flow(_key, _upper_is_src, _n_bytes, _pkt_ts);
}

u_int32_t flowHashTable::periodic_remove_deletable_flow(timeval * _now){
	u_int32_t i = 0;
	u_int32_t removed = 0;
	u_int32_t totRemoved = 0;
		
	while(i < listUpdateLim && flowNum > limFlowNum){
		// remove unused flowStruct from list
		if((removed = table[listToUpdate]->remove_deletable_list_flow()) > 0){
      totRemoved += removed;
      flowNum -= removed;
    }
		
    i++;
    
		listToUpdate++;
		if(listToUpdate == size)
			listToUpdate = 0;
	}

	return totRemoved;
}

void flowHashTable::print_flow_hash_table(){
  u_int32_t i = 0;
  
  timeval now;
  gettimeofday(&now, NULL);

  printf("\nPRINTING HASH TABLE ...\n");

  for(i=0; i<size; i++){
    if (table[i]!=NULL)
      table[i]->print_flow_list(&now);
    else
      printf("( NULL POINTER TO LIST )\n");
  }

  printf("... END HASH TABLE\n");

}
