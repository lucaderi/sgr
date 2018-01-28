#include <cstdlib>
#include <cstring>
#include <ctime>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libxml++/libxml++.h>

#include "mathUtil.h"
#include "trafficShaper.h"
#include "timeUtil.h"

#define DEFAULT_WAIT_TIME { 0, 1000 }

using namespace Glib;
using namespace std;
using namespace xmlpp;

trafficShaper::trafficShaper(char * _conf_file){
  u_int64_t tick_start, tick_delta;
  
  conf_file = strdup(_conf_file);
  
  mQueue = NULL;
  masterQueueNumber = 0;
  lastMasterQueue = 0;
  queueSize = 0;
  
  /* computing CPU frequence (code take from PF_RING example pfsend.c) */
  tick_start = rdtsc();
  usleep(1);
  tick_delta = rdtsc() - tick_start;

  tick_start = rdtsc();
  usleep(1001);
  cpuFreq = (rdtsc() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
}

trafficShaper::~trafficShaper(){
  int i;
  
  for(i=0; i<masterQueueNumber; i++){
    free(mQueue[i].queue.data);
  }
  
  free(mQueue);
  
  free(conf_file);
  conf_file = NULL;
  
  //delete this;
}

int trafficShaper::init_traffic_shaper(){
  int i;
  int _id = 0;
  int _w = 0;
  u_int16_t expected_queue_index = 0;
  
  Node * pNode;
	Node::NodeList::iterator iter;
	Node::NodeList nodeList;
	Element * nodeElem;
	Attribute * nodeAttr;
	ustring nodeName;
	
	DomParser parser;
	parser.set_substitute_entities();
	parser.parse_file(conf_file);
  
	if(!parser)
		return -1;
	
	nodeList = parser.get_document()->get_root_node()->get_children("queueSet");

  if(nodeList.size() != 1)
    return -1;

  pNode = nodeList.front();
	nodeElem = dynamic_cast<Element*>(pNode);
  
  nodeAttr = nodeElem->get_attribute("masterQueueNumber");
	if(!nodeAttr)
		return -1;
  
  masterQueueNumber = atoi(nodeAttr->get_value().c_str());
  if(masterQueueNumber <= 0)
    return -1;
	
  masterQueueNumberLim = masterQueueNumber - 1;
  
	nodeAttr = nodeElem->get_attribute("queueSize");
	if(!nodeAttr)
		return -1;
  
  queueSize = atoi(nodeAttr->get_value().c_str());
  if(queueSize <= 0)
    return -1;
  
  queueSize = roundup_to_2_power(queueSize);
  queueSizeLim = queueSize - 1;
  
  // initial allocation
  mQueue = (masterQueue_t *)calloc(masterQueueNumber, sizeof(masterQueue_t));
  if(mQueue == NULL)
    return -1;
  for(i=0; i<masterQueueNumber; i++){
    mQueue[i].queue.data = (recv_pkt_t **)calloc(queueSize, sizeof(recv_pkt_t *));
    if(mQueue[i].queue.data == NULL)
      return -1;
  }
  
  nodeList = pNode->get_children();
  for(iter = nodeList.begin(), expected_queue_index = 0; iter != nodeList.end(), expected_queue_index < masterQueueNumber; ++iter){
		pNode = * iter;
		nodeElem = dynamic_cast<Element*>(pNode);
		nodeName = pNode->get_name();
		
		if(strcmp(nodeName.c_str(), "queue") == 0){
      nodeAttr = nodeElem->get_attribute("id");
			if(!nodeAttr){
				printf("[ trafficShaper ] Format of queue invalid ! Attribute 'id' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
			_id = atoi(nodeAttr->get_value().c_str());
      
      if(_id != expected_queue_index){
        printf("[ trafficShaper ] Unexpected ID ! (line %d)\n", nodeElem->get_line());
        return -1;
      }
      
			nodeAttr = nodeElem->get_attribute("bandwidth");
      if(!nodeAttr){
				printf("[ trafficShaper ] Format of queue invalid ! Attribute 'bandwidth' needed ! Skipped ! (line %d)\n", nodeElem->get_line());
				continue;
			}
      _w = atoi(nodeAttr->get_value().c_str());
      
      if(_w <= 0){
        printf("[ trafficShaper ] Can't use negative bandwidth ! (line %d)\n", nodeElem->get_line());
        return -1;
      }
      
      mQueue[_id].weight = _w * 1024; // kBytes -> bytes
      
      expected_queue_index++;
    }else{
      //printf("FIND %s (possibly indentation !)\n", nodeName.c_str());
    }
  }
  
  return 0;
}

bool trafficShaper::enqueue_packet(u_int16_t _mq, recv_pkt_t * _pRP){
  queue_t * q = &(mQueue[_mq].queue);
  
  pthread_mutex_lock(&(q->m));
  
  if(isFull(q)){
    pthread_mutex_unlock(&(q->m));
    return false;
  }
  
  q->data[q->tail] = _pRP;
  
  q->tail = idx_incr(q->tail);
  
  pthread_mutex_unlock(&(q->m));
  
  return true;
}

recv_pkt_t * trafficShaper::dequeue_packet(){
  masterQueue_t * mq = NULL;
  queue_t * q = NULL;
  u_int64_t t, t_delta;
  u_int32_t credit;
  recv_pkt_t * pRP = NULL;
  
  bool found = false;
  static const struct timespec wait_time = DEFAULT_WAIT_TIME;
  
  u_int16_t firstMasterQueue = lastMasterQueue;
  
  while(!found){
    mq = &(mQueue[lastMasterQueue]);
    
    /* update master queue status */
    t = rdtsc();
    t_delta = t - mq->lastVisitTick;
    
    mq->lastVisitTick = t;
    
    credit = (u_int32_t) ((double) mq->weight * ((double) t_delta / cpuFreq));
    
    mq->token += credit;
    if(mq->token > mq->weight)
      mq->token = mq->weight;
    
    /* search in queue for a packet to send */
    q = &(mQueue[lastMasterQueue].queue);
    
    if(!isEmpty(q) && (mq->token >= q->data[q->head]->_caplen)){
      mq->token -= q->data[q->head]->_caplen;
      
      pRP = q->data[q->head];
      q->data[q->head] = NULL;
      
      q->head = idx_incr(q->head);
      
      found = true;
    }
    
    mQueue_incr();
    
    if(!found && lastMasterQueue == firstMasterQueue){
      nanosleep(&wait_time, NULL);
    }
  }
  
  return pRP;
}
