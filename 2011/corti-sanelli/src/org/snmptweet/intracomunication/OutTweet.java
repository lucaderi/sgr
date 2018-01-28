package org.snmptweet.intracomunication;
import org.snmptweet.snmptrap.MibParser;

import snmp.SNMPIPAddress;
import snmp.SNMPObjectIdentifier;
import snmp.SNMPSequence;

/**
 * This class is used for intracomunication between two thread
 * @author Michael Sanelli & Nicola Corti
 *
 */
public interface OutTweet {
	
	/**
	 * Setter for all the required identifier of the Trap
	 * @param serno SerialNumber of the Trap
	 * @param comm The Community
	 * @param agadr Agent Address
	 * @param gener Generic Trap ID
	 * @param specif Specific Trap ID
	 * @param time Datetime
	 * @param enterprise Enterprise ID
	 * @param varlist List of variable in the trap
	 */
	public void setTrapParam( int serno,
			String comm,
			SNMPIPAddress agadr,
			int gener,
			int specif,
			long time,
			SNMPObjectIdentifier enterprise,
			SNMPSequence varlist);

	// Print Methods
	/**
	 * Composes the message with the data of the trap. Verbose mode
	 * @param parser The parser of MIB
	 * @return Return the message
	 */
	public String composeExtendedMessage(MibParser parser);
	/**
	 * Composes the message with the data of the trap
	 * @param parser The parser of MIB
	 * @return Return the message
	 */
    public String composeAllMessage(MibParser parser);
	/**
	 * Composes the message with the data of the trap without use the parser
	 * @return Return the message
	 */
    public String composeSNMPMessage();

    // Trap Extract Methods
    /**
     * Return the Community identifier of the Trap
     * @return Community of the trap
     */
    public String getCommunity();
    /**
     * Return the agent ip address
     * @return the agent ip address
     */
    public SNMPIPAddress getAgentAddress();
    /**
     * Return the generic trap type 
     * @return Generic trap type
     */
    public String getGenericTrapType();
    /**
     * Return the specified trap type 
     * @return Specified trap type
     */
    public int getSpecificTrapType();
    /**
     * Return the timestamp of the Trap
     * @return timestamp of the Trap
     */
    public long getTimeStamp();
    /**
     * Return the OID of the trap
     * @return OID of the trap
     */
    public SNMPObjectIdentifier getEnterpriseOID();
    
	/**
	 * This return the SerialNumber of the Trap
	 * @return The SerialNumber of the Trap
	 */
	public int getSerialNumber();
	
}