package org.snmptweet.intracomunication;

import java.util.NoSuchElementException;
import java.util.Vector;

/**
 * This interface is used to make two threads communicate
 * @author Nicola Corti & Michael Sanelli
 *
 */
public class QueueSynchronized {
	/** This implements the queue structure */
	Vector<OutTweet> queue;
	
	/** 
	 * Constructor of the class QueueSynchronized
	 */
	public QueueSynchronized() {
		super();
		this.queue = new Vector<OutTweet>();
	}
	
	/**
	 * This add a message in the Queue structure
	 * @param trans The message that we want to send
	 */
	public synchronized void push(OutTweet trans) {
		this.queue.add(trans);
		this.notifyAll();
	}

	/**
	 * This remove a message from the queue structure. 
	 * If there aren't messages to read, Thread will wait until a message arrive  
	 * @return The message
	 * @throws InterruptedException If a interrupt arrive until the thread wait a message
	 */
	public synchronized OutTweet pop() throws InterruptedException {
		OutTweet retv=null;
		while (retv == null) {
			try {
				retv = this.queue.firstElement();
				this.queue.remove(0);
			}
			catch (NoSuchElementException e) {
				this.wait();
			}
		}
		
		return retv;
	}

	/**
	 * This method return the number of message in the queue structure
	 * @return The number of message memorized
	 */
	public int size() {
		return this.queue.size();
	}
}