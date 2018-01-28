package org.snmptweet.snmptrap;

import java.net.SocketException;

import org.snmptweet.conf.Environment;
import org.snmptweet.conf.SingleTonEnvironment;

import snmp.SNMPTrapReceiverInterface;

/**
 * This class is used for add a Trap V1 listener
 * @author Michael Sanelli & Nicola Corti
 *
 */
public class TrapReceiver {
	/** This contains the configuration of the server */
	private Environment env;
	/** Interface used to receive incoming traps */
	private SNMPTrapReceiverInterface traprecv;
	
	/**
	 * This is the basic costructor of TrapReceiver Class
	 */
	public TrapReceiver() {
		super();
		this.env = SingleTonEnvironment.getIstance();
		this.traprecv = null;
	}
	
	/**
	 * Initialize the socket binding and listener for the trap on the specified port
	 * @throws SocketException If the port are unusable
	 */
	public void initialize() throws SocketException{
		traprecv = new SNMPTrapReceiverInterface(env.getPort());
		traprecv.addv1TrapListener(new ListenTrapV1());
	}
	
	/**
	 * Start listening traps.
	 */
	public void startReceive() {
		this.traprecv.startReceiving();
	}
}
