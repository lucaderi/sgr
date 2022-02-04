package org.snmptweet.snmptrap;

import org.snmptweet.conf.Environment;
import org.snmptweet.conf.SingleTonEnvironment;
import org.snmptweet.intracomunication.*;

import snmp.SNMPv1TrapListener;
import snmp.SNMPv1TrapPDU;

/**
 * Implementation of the interface SNMPv1TrapListener for read the Snmp Trap
 * @author Nicola Corti & Michael Sanelli
 */
public class ListenTrapV1 implements SNMPv1TrapListener{
	/** Environment containing server's configuration */
	Environment env;
	/** Queue with received traps */
	QueueSynchronized queue;
	/** Serial number used to identify a trap */
	int serial;
	
	public ListenTrapV1() {
		super();
		this.env = SingleTonEnvironment.getIstance();
		this.queue = env.getQueueSynchronized();
		this.serial=0;
	}
	
	public void processv1Trap(SNMPv1TrapPDU pdu, String community) {
		this.serial++;
		OutTweetTrapV1 tosent = new OutTweetTrapV1();
		tosent.setTrapParam(this.serial, community, pdu.getAgentAddress(), pdu.getGenericTrap(), pdu.getSpecificTrap(), pdu.getTimestamp(), pdu.getEnterpriseOID(), pdu.getVarBindList());
		env.printLogFile("RECEIVED: " + tosent.composeAllMessage(env.getMibParser()), false);
		queue.push(tosent);
	}
	
}
