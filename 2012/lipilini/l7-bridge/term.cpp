#include "globals.h"

static int i;

void destroyRecvPktArray(){
  if(verbose_mode)
		printf("Destroying recv pkt array ... ");
  
	free(recv_pkt_array);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyFlowHTArray(){
  if(verbose_mode)
    printf("Destroying flow hash table array ... ");
  
	for(i=0; i<thread_number; i++){
    delete(hash_table_array[i]);
  }
  
  delete[] hash_table_array;
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyIPQDetStructArray(){
  if(verbose_mode)
    printf("Destroying ipoque detection struct array ... ");
  
	for (i=0; i<thread_number; i++){
    ipoque_exit_detection_module(ipoque_struct_array[i], free_wrapper);
  }
  
  delete[] ipoque_struct_array;
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyLocalTIDArray(){
  if(verbose_mode)
		printf("Destroying local thread id array ... ");
  
	delete[] local_tid_array;
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyMonitorThreads(){
  if(verbose_mode)
    printf("Destroying monitor threads ... ");
  
	for (i=0; i<thread_number; i++){
    pthread_cancel(pthread_array[i]);
    pthread_join(pthread_array[i], NULL);
  }

  delete[] pthread_array;
  
  if(verbose_mode)
    printf("DONE !\n");
}

void waitSignalHandlerThread(){
  if(verbose_mode)
    printf("Waiting signal handler thread ... ");
            
	pthread_join(signalHandlerTID, NULL);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyTrafficShaperThread(){
  if(verbose_mode)
    printf("Destroying traffic shaper thread ... ");
  
  pthread_cancel(trafficShaperTID);
	pthread_join(trafficShaperTID, NULL);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void destroyQueueArray(){
  if(verbose_mode)
    printf("Destroying queues for communications dispatcher-threads ... ");
  
	for(i=0; i<thread_number; i++){
    delete dismon_queue_array[i];
  }
  
  delete[] dismon_queue_array;
  
  if(verbose_mode)
    printf("DONE !\n");
}

void termPFRingBundle(){
  if(verbose_mode)
    printf("Terminating pf_ring bundle ... ");
  
	pfring_bundle_close(pfb);
  free(pfb);
  
  free(app_name);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void termPFRingIn(){
  if(verbose_mode)
    printf("Terminating pf_ring for IN device ... ");
  
	//pfring_disable_ring(in_pfr);
	free(in_device);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void termPFRingOut(){
  if(verbose_mode)
    printf("Terminating pf_ring for OUT device ... ");
  
	//pfring_disable_ring(out_pfr);
	free(out_device);
  
  if(verbose_mode)
    printf("DONE !\n");
}

void termRuleManager(){
  if(verbose_mode)
		printf("Terminating rule manager ... ");
	
	delete rM;
  
  if(conf_file != NULL){
    free(conf_file);
    conf_file = NULL;
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}

void termTrafficShaper(){
  if(verbose_mode)
    printf("Terminating traffic shaper ... ");
  
  delete tS;
  
  if(conf_file != NULL){
    free(conf_file);
    conf_file = NULL;
  }
  
  if(verbose_mode)
    printf("DONE !\n");
}
