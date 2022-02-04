/**
 * Key Container Class
 * 
 * This class is used for serialize the access on twitter.
 * @author Michael Sanelli & Nicola Corti
 * @year 2011
 */

package org.snmptweet.twitter;
import java.io.*;

/**
 * This class is used for serialize the access on twitter.
 */
public class KeyContainer implements Serializable {
	
	/** UID used for serialization */
	private static final long serialVersionUID = 1L;
	/** Macro containing KeyContainer serialized file name */
	private static final String KEYS_FILENAME = "keys.dat";
	/** Boolean value used for know if KeyContainer contain an access token */
	private boolean hastoken;
	/** SNMP Tweet consumer key */
	private String consumer;
	/** SNMP Tweeh consumer secret key */
	private String consumersecret;
	/** User access Token key */
	private String token;
	/** User access Token secret key */
	private String tokensecret;
	
	/**
	 * Constructor used to create a new KeyContainer with
	 * SNMP Tweet consumer keys.
	 */
	public KeyContainer(){
		super();
		this.hastoken = false;
		this.consumer = "5EPAag0iguaXtRaO9fvA";
		this.consumersecret = "zcVUGgtcUxqZI1nHLhqDmzt2jZDiQENmsgqDB2Vc";
	}
	
	/**
	 * Constructor used to create a new KeyContainer
	 * without User access token
	 * @param cons Application consumer key
	 * @param secret Application secret consumer key
	 */
	public KeyContainer(String cons, String secret){
		super();
		this.hastoken = false;
		this.consumer = cons;
		this.consumersecret = secret;
	}
	
	/**
	 * Constructor used to create a new KeyContainer
	 * with a User access token
	 * @param cons Application consumer key
	 * @param secret Application secret consumer key
	 * @param token User access token key
	 * @param tokensecret User access secret token key
	 */
	public KeyContainer(String cons, String secret, String token, String tokensecret){
		super();
		this.hastoken = false;
		this.consumer = cons;
		this.consumersecret = secret;
		this.token = token;
		this.tokensecret = tokensecret;
	}
	
	
	/**
	 * Method used to serialize a KeyContainer object.
	 * File name depend on KEYS_FILENAME macro
	 * @throws Exception Execption on serializing object
	 */
	public void serialize() throws Exception{
		
		ObjectOutputStream outstream = null;
		try{
			outstream = new ObjectOutputStream(new FileOutputStream(KEYS_FILENAME));
			outstream.writeObject(this);
			outstream.close();
		} catch (Exception e) {
			throw new Exception("KeyContainer.Serialize");
		}
		
	}
	
	
	/**
	 * Method used to deserialize a KeyContainer object.
	 * File name depend on KEYS_FILENAME macro
	 * @throws Exception Execption on deserializing object
	 */
	public static KeyContainer deSerialize() throws Exception{
		ObjectInputStream instream = null;
		try{
			instream = new ObjectInputStream(new FileInputStream(KEYS_FILENAME));
			KeyContainer readobj = (KeyContainer) instream.readObject();
			instream.close();
			return readobj;
		} catch (Exception e) {
			throw new Exception("KeyContainer.DeSerialize");
		}
	}

	
	/**
	 * Method used to check if KeyContainer contains user access token keys
	 * @return true if KeyContainer contains user keys, false otherwise
	 */
	public boolean isHastoken() {
		return hastoken;
	}

	/**
	 * Method used to set hastoken flag
	 * @param hastoken new hastoken value
	 */
	public void setHastoken(boolean hastoken) {
		this.hastoken = hastoken;
	}

	/**
	 * Method used to get Consumer key
	 * @return Consumer key
	 */
	public String getConsumer() {
		return consumer;
	}

	/**
	 * Methoud used to set a new Consumer key
	 * @param consumer new Consumer key
	 */
	public void setConsumer(String consumer) {
		this.consumer = consumer;
	}

	/**
	 * Method used to get Consumer secret key
	 * @return Consumer secret key
	 */
	public String getConsumersecret() {
		return consumersecret;
	}

	/** 
	 * Methoud used to set a new Consumer secret key
	 * @param consumersecret new Consumer secret key
	 */
	public void setConsumersecret(String consumersecret) {
		this.consumersecret = consumersecret;
	}

	/**
	 * Method used to get User access token key
	 * @return User access token key
	 */
	public String getToken() {
		return token;
	}

	/** 
	 * Methoud used to set a new User access token key
	 * @param token new User access token key
	 */
	public void setToken(String token) {
		this.token = token;
	}

	/**
	 * Method used to get User access token secret key
	 * @return User access token secret key
	 */
	public String getTokensecret() {
		return tokensecret;
	}

	/** 
	 * Methoud used to set a new User access token secret key
	 * @param tokensecret new User access token secret key
	 */
	public void setTokensecret(String tokensecret) {
		this.tokensecret = tokensecret;
	}
}
