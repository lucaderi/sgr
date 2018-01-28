#include "globals.h"

void * signalHandlerThread(void * arg){
	int e;
	int sig;
	
	// mask all signal
	sigset_t set;
	sigfillset(&set);
	pthread_sigmask(SIG_SETMASK, &set, NULL);
	
	// wait mask signal
	sigset_t waitset;
	sigemptyset(&waitset);
	
	// wait signal for update rule
	sigaddset(&waitset, SIGALRM);
	sigaddset(&waitset, SIGUSR1);
	
	// wait signal for termination
	sigaddset(&waitset, SIGINT);
	sigaddset(&waitset, SIGQUIT);
	sigaddset(&waitset, SIGTERM);
	
	// wait signal for internal error
	sigaddset(&waitset, SIGABRT);
	sigaddset(&waitset, SIGSEGV);
	
	while(!exit_condition){
		sigwait(&waitset, &sig);
		
		switch(sig){
			case SIGINT:
      case SIGQUIT:
      case SIGTERM:
				if(verbose_mode)
					printf("[ signalHandlerThread ] Received signal for quit ...\n");
        
				exit_condition = 1;
        
				break;
			case SIGALRM:
				if(verbose_mode)
					printf("[ signalHandlerThread ] Deleting old rule ...\n");
				
				rM->delete_oldies();
				
				if(verbose_mode)
					printf("[ signalHandlerThread ] Old rule deleted !\n");
				break;
			case SIGUSR1:
				if(verbose_mode)
					printf("[ signalHandlerThread ] Updating rule ...\n");
				
				e = rM->update_rule();
				
				if(e == UPDATE_TIME_ERROR){
					printf("[ signalHandlerThread ] Waiting for previous rule update !\n");
				}
				else if(e == UPDATE_MAKE_ERROR){
					printf("[ signalHandlerThread ] Error while parsing rule file ! Preserved old rule !\n");
				}
				else{
					alarm(2);
					if(verbose_mode)
						printf("[ signalHandlerThread ] Rule Updated !\n");
				}
				
				break;
			case SIGABRT:
			case SIGSEGV:
				printf("[ signalHandlerThread ] Internal error ! Quitting ...\n");
				exit_condition = 1;
				break;
		}
	}
	
	pthread_exit(NULL);
}
