#ifndef _ARRAYQUEUE_H_
#define _ARRAYQUEUE_H_

#include <cstdlib>
#include <pthread.h>

#include "globalTypes.h"
#include "mathUtil.h"

class ArrayQueue
{  
	private:
		recv_pkt_t ** data;
    pthread_mutex_t m;
		pthread_cond_t c;
		u_int32_t size;
    u_int32_t sizeLim;
		u_int32_t head;
		u_int32_t tail;
    
  protected:
    __inline__ u_int32_t idx_incr(u_int32_t _idx) { return( (_idx == sizeLim) ? 0 : _idx + 1 ); }
    __inline__ bool isEmpty() { return (data[head] == NULL); }
    __inline__ bool isFull() { return (data[tail] != NULL); }
		
	public:
		ArrayQueue(u_int32_t _size){
			data = (recv_pkt_t **)calloc(_size, sizeof(recv_pkt_t *));
			
      pthread_mutex_init(&m, NULL);
			pthread_cond_init(&c, NULL);
      
			size = roundup_to_2_power(_size);
      sizeLim = size - 1;
			head = 0;
			tail = 0;
		}
		
		~ArrayQueue(){
			free(data);
		}      
 
		bool Enqueue(recv_pkt_t * _pRP){
			
      if(isFull())
        return false;
			
			data[tail] = _pRP;
		
      tail = idx_incr(tail);
      
      pthread_cond_signal(&c);
		
			return true;
		}    

		recv_pkt_t * Dequeue(){
			recv_pkt_t * tmp;
	            
      if(isEmpty()){
        pthread_mutex_lock(&m);
        pthread_cond_wait(&c, &m);
        pthread_mutex_unlock(&m);
      }
			
			tmp = data[head];
      data[head] = NULL;
		
			head = idx_incr(head);

			return tmp;   
		}      
};

#endif // _ARRAYQUEUE_H_
