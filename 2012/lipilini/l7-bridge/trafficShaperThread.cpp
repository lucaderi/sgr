#include "globals.h"

static void forward_pkt(recv_pkt_t * _forwarding_pkt){
  int e = 0;
  
  if(_forwarding_pkt->_rx_if_index == in_idx){
		e = pfring_send(out_pfr, (char *)_forwarding_pkt->p, _forwarding_pkt->_caplen, 1);
		if(e < 0){
			printf("[ trafficShaper ] Can't send packet to OUT ...\n");
		}else{
			if(verbose_mode)
				printf("[ trafficShaper ] Sent %d bytes to OUT !\n", e);
		}
  }else{
		e = pfring_send(in_pfr, (char *)_forwarding_pkt->p, _forwarding_pkt->_caplen, 1);
		if(e < 0){
			printf("[ trafficShaper ] Can't send packet to IN ...\n");
		}else{
			if(verbose_mode)
				printf("[ trafficShaper ] Sent %d bytes to IN !\n", e);
		}
  }
  
  return;
}

void * trafficShaperThread(void * arg){
  recv_pkt_t * pRP = NULL;
  u_int32_t sent_packet = 0;
  
  // mask all signal
	sigset_t set;
	sigfillset(&set);
	pthread_sigmask(SIG_SETMASK, &set, NULL);
  
  while(!exit_condition){
    sent_packet = 0;
    
    while(sent_packet < pkt_to_send){
      pRP = tS->dequeue_packet();

      forward_pkt(pRP);

      sent_packet++;

      // mark slot for packet as available
      ATOMIC_RL(&(pRP->in_use));
      if(verbose_mode)
        printf("[ trafficShaper ] Packet processed ! Slot released ...\n");
    }
    
    nanosleep(&time_to_wait, NULL);
  }
  
  pthread_exit(NULL);
}
