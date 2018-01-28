package org.snmptweet.intracomunication;
import org.snmptweet.snmptrap.MibParser;

import snmp.*;

/**
 * This class is used for intracomunication between two thread
 * @author Michael Sanelli & Nicola Corti
 *
 */
public class OutTweetTrapV1 implements OutTweet {
	
	/** Serial Number of the Trap */
	int serialnum;
	/** Community of the Trap */
	String community;
	/** Agent Address that has sent the trap */
	SNMPIPAddress agentaddress;
	/** Generic Trap ID */
	int generictrap;
	/** Specifiec Trap ID */
	int specifictrap;
	/** Timestamp of Receiving Trap */
	long timestamp;
	/** Object Identifier of the Trap */
	SNMPObjectIdentifier enterpriseoid;
	/** VarBindList of the Trap */
	SNMPSequence varbindlist;
	/** Constructor of the class OutTweetTrapV1 */
	public OutTweetTrapV1() { super(); }
	
	/** Setter for all the required identifier of the Trap
	 * 	 * @param serno SerialNumber of the Trap
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
							SNMPSequence varlist)
	{
		this.serialnum = serno;
		this.community = new String(comm);
		this.agentaddress = agadr;
		this.generictrap = gener;
		this.specifictrap = specif;
		this.timestamp = time;
		this.enterpriseoid = enterprise;
		this.varbindlist = varlist;
	}

	/**
	 * Convert the TimeTicks into a Human Readable time
	 * @param time timeticks
	 * @return Time
	 */
	private String convertTimetricks(long time) {
		String uptime = new String();
		time /= 100;
		short temp=0, i=3;
		while (time != 0 && i != 0) {
			temp=(short) (time%60);
			if (uptime.isEmpty()) {
				uptime += temp;
			}
			else {
				uptime = temp + ":" + uptime;	
			}
			if (temp < 10) uptime = "0" + uptime;
			time /= 60;
			i--;
		}
		if (time != 0) {
			temp = (short)(time%30);
			uptime = temp + " Days " + uptime;
			time /= 30;
			temp = (short)(time%12);
			uptime = temp + " Month " + uptime;
			time /= 12;
			uptime = temp + " Years " + uptime;
		}
		return uptime;
	}
	
	/**
	 * Composes the message with the data of the trap. Verbose mode
	 * @param parser The parser of MIB
	 * @return Return the message
	 */
	public String composeExtendedMessage(MibParser parser) {
		String outstring = new String("");
	    outstring += "=== TRAP PRINT ===";
		outstring += ("SERIAL NO: " + this.serialnum + "\n");
		outstring += ("COMMUNITY: " + this.community + "\n");
		outstring += ("AGENT IP: " + this.agentaddress.toString() + "\n");
		outstring += ("GENERIC TRAP TYPE: " + genericTrapParser(this.generictrap) + "\n");
		outstring += ("SPECIFIC TRAP TYPE: " + this.specifictrap + "\n");
		outstring += ("TIME STAMP: " + convertTimetricks(this.timestamp) + "\n");
		outstring += ("ENTERPRISE OID: ");
		if (parser != null)
			outstring += (parser.convertOid(this.enterpriseoid, false) + "\n");
		else
			outstring += (this.enterpriseoid.getValue() + "\n");
		return outstring;
	}
	
	
	/**
	 * Composes the message with the data of the trap
	 * @param parser The parser of MIB
	 * @return Return the message
	 */
	public String composeAllMessage(MibParser parser) {
		String outstring = new String("");	
		outstring += (this.serialnum + " ");
		outstring += (this.community + " ");
		outstring += (this.agentaddress.toString() + " ");
		outstring += (genericTrapParser(this.generictrap) + " ");
		outstring += (this.specifictrap + " ");
		outstring += (convertTimetricks(this.timestamp) + " ");
		if (parser != null)
			outstring += (parser.convertOid(this.enterpriseoid, false) + " ");
		else
			outstring += (this.enterpriseoid.getValue() + " ");
		outstring += (this.composeSequence(this.varbindlist, parser));
		return outstring;
	}
	
	
	/**
	 * Composes the message with the data of the trap without using the parser
	 * @return Return the message
	 */
	public String composeSNMPMessage() {
		String outstring = new String("");
		outstring += (this.community + " ");
		outstring += (this.agentaddress.toString() + " ");
		outstring += (genericTrapParser(this.generictrap) + " ");
		outstring += (this.specifictrap + " ");
		outstring += (this.timestamp + " ");
		outstring += (this.enterpriseoid + " ");
		return outstring;
	}
	
	
	/**
	 * This return the SerialNumber of the Trap
	 * @return The SerialNumber of the Trap
	 */
	public int getSerialNumber() { return this.serialnum; }
	
    /**
     * Return the Community identifier of the Trap
     * @return Community of the trap
     */
	public String getCommunity() { return this.community; }
	
    /**
     * Return the agent ip address
     * @return the agent ip address
     */
	public SNMPIPAddress getAgentAddress() { return this.agentaddress; }
	
    /**
     * Return the generic trap type 
     * @return Generic trap type
     */
	public String getGenericTrapType() { return genericTrapParser(this.generictrap); }
	
    /**
     * Return the specified trap type 
     * @return Specified trap type
     */
	public int getSpecificTrapType() { return this.specifictrap; }
	
    /**
     * Return the timestamp of the Trap
     * @return timestamp of the Trap
     */
	public long getTimeStamp() { return this.timestamp; }
	
    /**
     * Return the OID of the trap
     * @return OID of the trap
     */
	public SNMPObjectIdentifier getEnterpriseOID() { return this.enterpriseoid; }
	
	/**
	 * Method used to get trap type to string
	 * @param trapvalue Trap type number
	 * @return A string containing trap type
	 */
	private String genericTrapParser(int trapvalue){
		String traptype = null;
		switch (trapvalue) {
			case 0: traptype = "Cold Start"; break;
			case 1: traptype = "Warm Start"; break;
			case 2: traptype = "Link Down"; break;
			case 3: traptype = "Link Up"; break;
			case 4: traptype = "Authentication Failure"; break;
			case 5: traptype = "Egp Neighbor Loss"; break;
			case 6: traptype = "Enterprise Specific"; break;
			default:traptype = "Trap Error"; break;
		}
		return traptype;		
	}
	
	/**This method compose string from a SNMPSequence object,
	 * parsing Oid with a MibParser
	 * 
	 * @param seq The SNMPSequence object
	 * @param parser A Mib parser
	 * @return A string containing parsed value
	 */
	private String composeSequence(SNMPSequence seq, MibParser parser){
		String result = "";
		int i = 0;
		SNMPSequence pair = null;
		
		while(i < seq.size())
		{
			result += "- ";
			pair = (SNMPSequence)seq.getSNMPObjectAt(i);
			result += parser.convertOid((SNMPObjectIdentifier)pair.getSNMPObjectAt(0), true);
			result += " " + pair.getSNMPObjectAt(1).toString() + " "; 
			i++;
		}
		return result;
	}
}