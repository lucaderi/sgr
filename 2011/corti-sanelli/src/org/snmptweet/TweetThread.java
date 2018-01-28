/**
 * SNMP Tweet - Tweet Thread
 * 
 * This file contain the source code of tweet thread
 * used to send online received traps
 * 
 * @author Nicola Corti & Michael Sanelli
 * @year 2011
 *
 */

package org.snmptweet;

import org.snmptweet.conf.Environment;
import org.snmptweet.conf.SingleTonEnvironment;
import org.snmptweet.intracomunication.*;
import org.snmptweet.twitter.MyTwitter;

/**	This thread is used to send traps from a queue to twitter.
	*
	*	@author Nicola Corti & Michael Sanelli
	*/
public class TweetThread extends Thread {
	
	/** Twitter object, used to connect with twitter */
	MyTwitter twitter;
	/** Environment used to get execution information */
	Environment env;
	/** Queue of received traps to be sent */
	QueueSynchronized queue;
	
	/**	This constructor create a new thread 
		*	With default value
		*/ 
	public TweetThread() {
		super();
		this.env = SingleTonEnvironment.getIstance();
		this.queue = env.getQueueSynchronized();
		this.twitter = new MyTwitter();
		this.setName("Tweet Thread");
	}
	
	/**	This method is used to run the thread
		*/
	public void run(){
		
		this.twitter.handShaker();
				
		String message = null, user = null;
		OutTweet incomingtrap=null;
		
		while (true) {		
			try {
				/* Extraction of received trap from cue */
				incomingtrap = this.queue.pop();
			} catch (InterruptedException e) {
				this.env.printLogFile("Interrupt received", true);
				break;
			}
			
			/* Preparation of tweet message */
			user = this.env.getUser(incomingtrap.getAgentAddress().toString());
			message = "TRAP: " + incomingtrap.composeAllMessage(env.getMibParser());
			
			this.twitter.sendUpdate(user, message, incomingtrap.getSerialNumber(), env.getPrivateMode());
		} 
	}
	
	
	
}
