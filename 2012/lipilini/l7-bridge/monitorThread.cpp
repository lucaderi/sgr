#include "globals.h"

static void forward_pkt(recv_pkt_t * _forwarding_pkt, int _local_tid){
  int e = 0;
  
  if(_forwarding_pkt->_rx_if_index == in_idx){
		e = pfring_send(out_pfr, (char *)_forwarding_pkt->p, _forwarding_pkt->_caplen, 1);
		if(e < 0){
			printf("[ monitorThread %d ] Can't send packet to OUT ...\n", _local_tid);
		}else{
			if(verbose_mode)
				printf("[ monitorThread %d ] Sent %d bytes to OUT !\n", _local_tid, e);
		}
  }else{
		e = pfring_send(in_pfr, (char *)_forwarding_pkt->p, _forwarding_pkt->_caplen, 1);
		if(e < 0){
			printf("[ monitorThread %d ] Can't send packet to IN ...\n", _local_tid);
		}else{
			if(verbose_mode)
				printf("[ monitorThread %d ] Sent %d bytes to IN !\n", _local_tid, e);
		}
  }
  
  return;
}

void * monitorThread(void * arg){
	int local_tid = * (int *) arg;
  
  int e = 0;
  u_int32_t pkt_processed_num = 0;
  recv_pkt_t * _pkt;

  u_int64_t when = 0;
  ip_addr * ip;
  unsigned int detected_proto = 0;

  flowStruct * pFS = NULL;
  
  flowKey_t flow_key;
  bool upper_is_src;
  
  rule_ret_t _rR;
  u_int32_t _vers;
  
  timeval now;

  // retrieve thread private resource from local_tid
  ArrayQueue * queue_pointer = dismon_queue_array[local_tid];
  flowHashTable * fHT = hash_table_array[local_tid];
  struct ipoque_detection_module_struct * ipoque_struct = ipoque_struct_array[local_tid];
  
	bool allowed = false;
  bool b = false;
	
	// mask all signal
	sigset_t set;
	sigfillset(&set);
	pthread_sigmask(SIG_SETMASK, &set, NULL);

	
	while(!exit_condition){
    // dequeue pointer to packet to process
    _pkt = queue_pointer->Dequeue();
    
    // get actual time
    gettimeofday(&now, NULL);
    
    // update hash table
    pkt_processed_num++;
    
    if(pkt_processed_num > update_hash_table_interval){
			if(verbose_mode)
				printf("[ monitorThread %d ] Updating hash table ...\n", local_tid);
				
			e = fHT->periodic_remove_deletable_flow(&now);
			
			if(verbose_mode)
				printf("[ monitorThread %d ] Removed %d unused element in hash table !\n", local_tid, e);
			
			pkt_processed_num = 0;
		}

    // add packet to hash table
    build_flow_key(_pkt->_ip_version, _pkt->_ip_proto, &(_pkt->_src_ip), _pkt->_src_port, &(_pkt->_dst_ip), _pkt->_dst_port, &(flow_key), &(upper_is_src));
    
    pFS = fHT->add_new_capt_pkt(&(flow_key), upper_is_src, _pkt->_n_bytes, &(_pkt->_pkt_ts), &now);
    
    if(pFS == NULL){
			// hash table full ! mark slot for packet as available
			ATOMIC_RL(&(_pkt->in_use));
			
			printf("[ monitorThread %d ] Hash table is full ! Packet discarded !\n", local_tid);
			
			continue;
		}
    
    // get rule and update it in hash table if necessary
    if(likely(pFS->get_flow_rule_version() == (_vers = rM->get_rule_version()))){
      if(verbose_mode)
        printf("[ monitorThread %d ] Getting flow rule from copy stored in hash table ...\n", local_tid);
      
			_rR = pFS->get_flow_rule();
      
		}else{
      if(verbose_mode)
        printf("[ monitorThread %d ] Retrieving flow rule from rule manager ...\n", local_tid);
      
      _rR = rM->retrieve_rule(_pkt->_ip_version, (_pkt->_rx_if_index == in_idx) ? &(_pkt->_src_ip) : &(_pkt->_dst_ip));
      
			pFS->set_flow_rule(&_rR, _vers);
		}
		
		// really have to process packet ?????
		if(_rR.type == ALLOW_ALL){
      // forward packet
			forward_pkt(_pkt, local_tid);
        
      // mark slot for packet as available
      ATOMIC_RL(&(_pkt->in_use));
      if(verbose_mode)
        printf("[ monitorThread %d ] Packet processed (by ALLOW_ALL rule) ! Slot released ...\n", local_tid);
		}
		else if(_rR.type == DENY_ALL){
			// mark slot for packet as available
      ATOMIC_RL(&(_pkt->in_use));
      if(verbose_mode)
        printf("[ monitorThread %d ] Packet processed (by DENY_ALL rule) ! Slot released ...\n", local_tid);
		}
		else{
			// REAL PROCESS PACKET
			if((pFS->get_l7_proto() == IPOQUE_PROTOCOL_UNKNOWN) && (pFS->get_src_n_pkt() + pFS->get_dst_n_pkt() < n_pkt_limit)){
				if(verbose_mode)
					printf("[ monitorThread %d ] Detecting protocol ...\n", local_tid);

				when = ((u_int64_t) _pkt->_pkt_ts.tv_sec) * DEFAULT_TICK_RESOLUTION /* detection_tick_resolution */
								+ _pkt->_pkt_ts.tv_usec / (1000000 / DEFAULT_TICK_RESOLUTION) /* (1000000 / detection_tick_resolution) */;
        ip = &(_pkt->_src_ip);
        
        if(likely(_pkt->_ip_version == 4)){
          detected_proto = ipoque_detection_process_packet(ipoque_struct, pFS->get_addr_of_nDPI_flow(),
                  (u_char *) &((_pkt->p)[_pkt->_l3_offset]), _pkt->_n_bytes, when,
                  (equal_ipv4(pFS->get_src_ip()->v4, ip->v4)) ? pFS->get_addr_of_nDPI_src() : pFS->get_addr_of_nDPI_dst(),
                  (equal_ipv4(pFS->get_src_ip()->v4, ip->v4)) ? pFS->get_addr_of_nDPI_dst() : pFS->get_addr_of_nDPI_src());
        }
        else if(_pkt->_ip_version == 6){
          detected_proto = ipoque_detection_process_packet(ipoque_struct, pFS->get_addr_of_nDPI_flow(),
                  (u_char *) &((_pkt->p)[_pkt->_l3_offset]), _pkt->_n_bytes, when,
                  (equal_ipv6(pFS->get_src_ip()->v6, ip->v6)) ? pFS->get_addr_of_nDPI_src() : pFS->get_addr_of_nDPI_dst(),
                  (equal_ipv6(pFS->get_src_ip()->v6, ip->v6)) ? pFS->get_addr_of_nDPI_dst() : pFS->get_addr_of_nDPI_src());
        }
        else{
          // should never be here !
          detected_proto = IPOQUE_PROTOCOL_UNKNOWN;
        }

				if(detected_proto != IPOQUE_PROTOCOL_UNKNOWN){
					pFS->set_l7_proto(detected_proto);
					if(verbose_mode)
						printf("[ monitorThread %d ] Packet of l7 protocol %s found !\n", local_tid, protocol_long_str[detected_proto]);
					
					allowed = (IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(_rR.rule.pB, detected_proto) != 0);
						
				}else{
					if(verbose_mode)
						printf("[ monitorThread %d ] Packet of unknown protocol bridged !\n", local_tid);
					
					// have to know more on flow, so permit communication !
					allowed = true;
				}

			}else{
				// here if already detect protocol or reach n_pkt_limit
				detected_proto = pFS->get_l7_proto();
				
				if(verbose_mode)
					printf("[ monitorThread %d ] Flow already examined ! Protocol %s !\n", local_tid, protocol_long_str[detected_proto]);
					
				allowed = (IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(_rR.rule.pB, detected_proto) != 0);

			}
      
      // send packet on other interface if allowed
      if(allowed){
        if(_rR.rule.q[detected_proto] != -1){
          b = tS->enqueue_packet(_rR.rule.q[detected_proto], _pkt);
          if(b){
            if(verbose_mode)
              printf("[ monitorThread %d ] Packet enqueued to trafficShaper in queue %d !\n", local_tid, _rR.rule.q[detected_proto]);
          }else{
            printf("[ monitorThread %d ] Error while enqueuing packet to trafficShaper in queue %d !\n", local_tid, _rR.rule.q[detected_proto]);
          }
        }else{
          forward_pkt(_pkt, local_tid);

          // mark slot for packet as available
          ATOMIC_RL(&(_pkt->in_use));
          if(verbose_mode)
            printf("[ monitorThread %d ] Packet processed ! Slot released ...\n", local_tid);
        }
      }else{
        if(verbose_mode)
          printf("[ monitorThread %d ] Packet dropped !\n", local_tid);

        // mark slot for packet as available
        ATOMIC_RL(&(_pkt->in_use));
        if(verbose_mode)
          printf("[ monitorThread %d ] Packet processed ! Slot released ...\n", local_tid);
      }
		}
    
  }
	
	pthread_exit(NULL);
}
