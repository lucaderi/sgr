/*
 * myList.hpp
 *
 * \date 22/giu/2010
 * \author Daniele De Sensi (desensi@cli.di.unipi.it)
 *
 * Implementation of a bidirectional linked list. The elements are inserted to the head and removed from the tail of the list.
 * This list can be used with the fastflow's memory allocator.
 *
 */

#ifndef MYLIST_HPP_
#define MYLIST_HPP_
#include <allocator.hpp>

/**
 * A node of the list.
 */

template <typename T> class node{
public:
	T elem;
	node* prev;
	node* next;

	inline node(T e, node* p=NULL, node* n=NULL):elem(e),prev(p),next(n){;}

	inline void init(T e, node* p=NULL, node* n=NULL){
		elem=e;prev=p;next=n;
	}
};

/**
 * A generic list that can be used with standard allocator or with ff_allocator.
 */
template <typename T> class myList{
private:
	ff::ff_allocator* ffalloc; ///< An instance of ff_allocator
	node<T>* head; ///< The head of the list
	node<T>* tail; ///< The tail of the list
	int nElem; ///< Size of the list
	/**
	 * Dinamically allocates memory (with standard allocator or with ff_allocator)
	 */
	inline void* myMalloc(size_t size){
		if(ffalloc!=NULL)
			return ffalloc->malloc(size);
		else
			return malloc(size);
	}

	/**
	 * Frees memory dinamically allocated (with standard allocator or with ff_allocator)
	 */
	inline void myFree(void* p){
		if(ffalloc!=NULL)
			ffalloc->free(p);
		else
			free(p);
	}
public:
	/**
	 * Constructor of the list.
	 * \param alloc An instance of ff_allocator, if it isn't passed, new nodes are allocated with standard allocator.
	 */
	inline myList(ff::ff_allocator *alloc=NULL):ffalloc(alloc),head(NULL),tail(NULL),nElem(0){;}

	/**
	 * Initializes the list.
	 * \param alloc An instance of ff_allocator, if it isn't passed, new nodes are allocated with standard allocator.
	 */
	inline void init(ff::ff_allocator *alloc=NULL){
		ffalloc=alloc;head=tail=NULL;nElem=0;
	}

	/**
	 * Inserts a new element at the head of the list.
	 * \param x The element to insert.
	 */
	inline void push(T x){
		if(head==NULL){
			head=(node<T>*)myMalloc(sizeof(node<T>));
			head->init(x);
			tail=head;
		}else{
			node<T>* oldHead=head;
			head=(node<T>*)myMalloc(sizeof(node<T>));
			head->init(x,NULL,oldHead);
			oldHead->prev=head;
		}
		++nElem;
	}

	/**
	 * Removes an element from the tail of the list.
	 * \param x A pointer to a location where the element will be saved.
	 * \return -1 if no elements are present, otherwise returns 0.
	 */
	inline int pop(T* x){
		if(tail==NULL){
			return -1;
		}
		node<T>* toRemove=tail;
		*x=tail->elem;
		tail=tail->prev;
		if(tail!=NULL)
			tail->next=NULL;
		else
			head=NULL;
		myFree(toRemove);
		--nElem;
		return 0;
	}

	/**
	 * Returns the number of elements of the list.
	 * \return The number of elements of the list.
	 */
	inline int size(){
		return nElem;
	}
};

#endif /* MYLIST_HPP_ */
