/**
 * SNMP Tweet Listener Thread
 * 
 * This file contain the source code of listener thread
 * used to listen incoming snmp traps
 * 
 * @author Nicola Corti & Michael Sanelli
 * @year 2011
 *
 */

package org.snmptweet;
import java.net.SocketException;

import org.snmptweet.conf.*;
import org.snmptweet.snmptrap.*;

/**
 * Class containing Listener thread code.
 */
public class ListenerThread extends Thread {

	/** Environment used to get execution information */
	private Environment env;
	
	/** Thread constructor, used to get Environment instance */
	public ListenerThread(){
		super();
		this.env = SingleTonEnvironment.getIstance();
		this.setName("Listener Thread");
	}
	
	/**	This method is used to run the thread */
	public void run() {
		TrapReceiver traprecv = new TrapReceiver();
		try {
			traprecv.initialize();
		} catch (SocketException e) {
			this.env.printLogFile("Socket error ", true);
		}
		env.printLogFile("Start listening traps", false);
		traprecv.startReceive();
	}
}
