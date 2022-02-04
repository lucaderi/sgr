package org.snmptweet.conf;
import java.io.File;
import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.util.Hashtable;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.snmptweet.intracomunication.*;
import org.snmptweet.snmptrap.*;

/**
 * This file containts the Enviroment class
 * used to make interaction possible between all threads of project.
 * 
 * @author Nicola Corti & Michael Sanelli
 *
 */
public class Environment {
	/** Mib directory, used to found mib files */
	private File mibdir;
	/** Port used to listen incoming traps */
	private int port;
	/** Parser used to parse SNMP OID */
	private MibParser mibparser;
	/** Queue of incoming traps */
	private QueueSynchronized queuesync;
	/** String containing log file name */
	private String logfile;
	/** Logger used to write strings to logfile */
	private Logger logger;
	/** Hastable used to store association between IPs and User*/
	private Hashtable<String, String> hash;
	/** Flag used to check if tweet thread is running in private mode */
	private Boolean privateMode;
	
	/**
	 * This is a constructor of Environment Class.
	 * The new environment has got default value for all of it's field.
	 * 
	 * Default value are:
	 *	logfile = "./snmptweet.log"
	 *	mibdir = "./MIBS"
	 *	port = 1640;
	 *	private mode = false;
	 */
	public Environment(){
		super();
		this.logfile = "./snmptweet.log";
		this.mibdir = new File("./MIBS");
		if (!mibdir.exists()) mibdir.mkdir();
		this.port = 1640;
		this.privateMode = false;
		this.queuesync = new QueueSynchronized();
		this.hash = new Hashtable<String, String>();
	}
	
	/**
	 * Change value of Private Mode flag.
	 * @param value The new value to set to flag 
	 */
	public void setPrivateMode(Boolean value) {
		this.privateMode = value;
	}
	
	/**
	 * Return Private Mode flag value
	 * @return True if private mode is on, false in other case.
	 */
	public Boolean getPrivateMode() {
		return this.privateMode;
	}
	
	/**
	 * Change value of Mib directory
	 * @param mibdir String containing new Mib Directory path (mibdir need to not be null)
	 */
	public void setMibDir(String mibdir){
		this.mibdir = new File(mibdir);
	}
	
	/**
	 * Change value of port for listening incoming traps
	 * @param port Value of new port
	 */
	public void setPort(int port){
		this.port = port;
	}

	/**
	 * Change log file name
	 * @param logfile String containing new log file name
	 */
	public void setLogfile(String logfile) {
		this.logfile = logfile;
	}
	
	/**
	 * Return value of used port for listening threads
	 * @return Number of used port
	 */
	public int getPort(){
		return this.port;
	}
	
	/**
	 * Return log file name.
	 * @return String containing log file name
	 */
	public String getLogFile() {
		return this.logfile;
	}
	
	/**
	 * Return the MibParser
	 * Used to parse SNMP OID to string.
	 * After initialization this MibParser, contains Mibs loaded from Mibs directory.
	 * @return The MibParser
	 */
	public MibParser getMibParser(){
		return this.mibparser;
	}
	
	/**
	 * Return the path of Mib Directory.
	 * @return String containing Mib Directory
	 */
	public String getMibDir() {
		return this.mibdir.getName();
	}
	
	/**
	 * Return the Queue of received trap.
	 * @return A Queue containing all received trap
	 */
	public QueueSynchronized getQueueSynchronized(){
		return this.queuesync;
	}
	
	/**
	 * Add a new association into the hash table.
	 * @param ip String containing IP address of association
	 * @param user String containing Username associated with IP
	 */
	public void setAssociation(String ip, String user) {
		try {
			this.hash.put(ip, user);
		}
		catch (NullPointerException e) {
			this.printLogFile("Association set <ip, user> error", true);
		}
	}
	
	/**
	 * Find association for an IP address and return the related username.
	 * @param ip
	 * @return A string containing username related to IP, if no association is found, null is returned.
	 */
	public String getUser(String ip) {
		try {
			return this.hash.get(ip);
		}
		catch (NullPointerException e) {
			this.printLogFile("Association get <ip, user> error", true);
			return null;
		}
	}
	
	/**
	 * Initialize the environment and check if all parameters are correct.
	 * 
	 * @throws BindException Exception trown if it's impossibile to use the entered port.
	 * @throws SecurityException Exception trown if there's a log file security error.
	 * @throws IOException Exception trown if there's an I/O Error with LogFile or with Mib dir
	 */
	public void initialize() throws BindException, IOException, SecurityException {
		
		/* Try to open entered port for listening incoming traps. 
		 */
		ServerSocket test = null;
		try{
			test = new ServerSocket(this.port);
			test.close();
			test = null;
		} catch (IOException e){
			throw new BindException("Bind Port error");
		} catch (SecurityException e) {
			throw new SecurityException(e.getMessage());
		}
		
		/* Try to create a log file
		 * If logfile is null, no log file will be used.
		 */
		Properties props = new Properties();
		props.load(getClass().getResourceAsStream("/mylog.proprieties"));
		PropertyConfigurator.configure(props);

		this.logger = Logger.getLogger(this.getClass());
		
		/* Loads mib parser
		 */
		if (mibdir.exists()) {
			this.mibparser = new MibParser(mibdir);
		}
		else {
			throw new IOException("Mibdir not found");
		}
	}
	
	/**
	 * Print a new message to log file
	 * 
	 * @param message String containing message to be written
	 * @param warn If true the message is print as a WARN (used for error, or important message), otherwise it is print as an INFO
	 */
	public void printLogFile(String message, boolean warn) {		
		if (this.logfile != null){
			if(warn){
				this.logger.warn(message);
			} else {
				this.logger.info(message);
			}
		}
	}
	
	/**
	 * This function return a String representation Environment
	 * @return String reprenstation Environment
	 */
	public String toString() {
		return "Environment: MibDir " + this.mibdir.getName() + ", Port " + this.port + ", LogFile " + this.logfile + ", privateMode " + this.privateMode + ", Association <ip, user> entered : " + this.hash.toString();
	}
	
}
