/*
 * HashTable.hpp
 *
 * \date 14/mag/2010
 * \author Daniele De Sensi (desensi@cli.di.unipi.it)
 *
 * Implementation of the hash table used by the workers to insert the flows.
 */

#ifndef HASHTABLE_HPP_
#define HASHTABLE_HPP_
#include "myList.hpp"
#include <allocator.hpp>
#include <cassert>
#include <limits>



/**
 * Hash table
 */
class Hash{
private:
	node<hashElement*> **h,      ///<The hash table.
		*nextNodeToCheck; ///<Pointer to the last node checked.
	uint size,            ///<Number of row of the table.
		lastRowChecked,   ///<Index of last row checked.
		maxActiveFlows,   ///<Max number of active flows.
		activeFlows;	  ///<Number of active flows.
	ff::ff_allocator* ffalloc;  ///<Fastflow's allocator.
public:
	/**
	 * Constructor of the hash table.
	 * \param d Number of row of the table.
	 * \param maxActiveFlows Maximum number of active flows.
	 * \param ffalloc A pointer to the fastflow's memory allocator.
	 */
	Hash(uint d, uint maxActiveFlows, ff::ff_allocator* ffalloc):h(new node<hashElement*>*[d]),nextNodeToCheck(NULL),size(d),lastRowChecked(0)
	,maxActiveFlows(maxActiveFlows),activeFlows(0),ffalloc(ffalloc){
		for(uint i=0; i<d; i++){
			h[i]=NULL;
		}
	}

	/**
	 * Destructor of the hash table.
	 */
	~Hash(){
		node<hashElement*> *c,*k;
		for(uint i=0; i<size; i++){
			c=h[i];
			while(c!=NULL){
				k=c->next;
				delete c;
				c=k;
			}
		}
		delete[] h;
	}

	/**
	 * Adds (or updates) some flows. If the hash table has the max number of active flows, adds to l a flow and remove it from
	 * the hash table.
	 * \param flowsToAdd A list of flows to add.
	 * \param l A pointer to a list of expired flows.
	 * \return Returns the capture time (seconds) of the last packet added.
	 */
	int updateFlows(myList<hashElement*>* flowsToAdd, myList<hashElement*>* l){
		hashElement* f=NULL;
		while(flowsToAdd->size()!=0){
			flowsToAdd->pop(&f);
			uint i=f->hashId;
			assert(i<size);
			/**If the flow is the first that have i as value of hash function.**/
			if(h[i]==NULL){
				f->Last=f->First;
				f->dPkts=1;
				node<hashElement*> *newNode=new node<hashElement*>(f,NULL,NULL);
				h[i]=newNode;
				++activeFlows;
				if(activeFlows==maxActiveFlows)
					checkExpiration(1,0,0,l,NULL);
			}else{
				node<hashElement*> *p=h[i];
				hashElement* examinated;
				/**Searches the node.**/
				while(p!=NULL && !equals(p->elem,f)){
					p=p->next;
				}
				/**Updates flow.**/
				examinated=(p!=NULL)?p->elem:NULL;
				if(examinated && equals(examinated,f)){
					++(examinated->dPkts);
					examinated->dOctets+=f->dOctets;
					examinated->Last=f->First;
					examinated->tcp_flags|=f->tcp_flags;
					ffalloc->free(f);
				}else{
					/**Creates new flow and inserts it at the begin of the list.**/
					f->Last=f->First;
					f->dPkts=1;
					node<hashElement*> *newNode=new node<hashElement*>(f,NULL,h[i]);
					h[i]->prev=newNode;
					h[i]=newNode;
					++activeFlows;
					if(activeFlows==maxActiveFlows)
						checkExpiration(1,0,0,l,NULL);
				}
			}
		}
		return f!=NULL?f->First.tv_sec:0;
	}

	/**
	 * Checks if some flow is expired (max for n flows). Start from the last flow checked.
	 * \return A vector of expired flows.
	 * \param n Maximum number of flow to check.
	 * \param idle Max number of seconds of inactivity.
	 * \param lifeTime Max number of life's seconds of a flow.
	 * \param l A pointer to the list where to add the expired flows.
	 * \param now A pointer to current time value.
	 */
	void checkExpiration(int n, int idle, int lifetime, myList<hashElement*>* l, time_t* now){
		if(n==0 || n<-1) return;
		uint nodeChecked=0,lineChecked=0,limit;
		node<hashElement*> *p=nextNodeToCheck,*temp;
		/**If n==-1 checks all flows in the hash table.**/
		if(n==-1) limit=std::numeric_limits<uint>::max();
		else limit=n;
		while(nodeChecked<limit && lineChecked<=size){
			if(p!=NULL){
				++nodeChecked;
				/**If the flow is expired, adds the flow to the vector.**/
				if(isExpired(p->elem,idle,lifetime,now)){
					l->push(p->elem);
					if(p->prev!=NULL)
						p->prev->next=p->next;
					else{
						h[lastRowChecked]=p->next;
					}
					if(p->next!=NULL)
						p->next->prev=p->prev;
					temp=p->next;
					delete p;
					p=temp;
					--activeFlows;
				}else
					p=p->next;
			/**If the end of the row is arrived, checks the next row.**/
			}else{
				++lineChecked;
				lastRowChecked=(lastRowChecked+1)%size;
				p=h[lastRowChecked];
			}
		}
		/**Updates the pointer to the next node to check.**/
		nextNodeToCheck=p;
	}
};


/**
 * Computes the hash function on a flow.
 * \param f The flow.
 * \param mod Size of the hash table (Size(hashT1)+Size(hashT2)+....+Size(hashTn))
 * \return Hash(f)%Mod
 */
inline int hashFun(hashElement* f,int mod){
	return (f->dstaddr+f->srcaddr+f->prot+f->srcport+f->dstport+f->tos)%mod;
}


#endif /* HASHTABLE_HPP_ */
