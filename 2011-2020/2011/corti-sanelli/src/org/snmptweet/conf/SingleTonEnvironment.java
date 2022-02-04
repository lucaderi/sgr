package org.snmptweet.conf;

/**This class is used for implementing Environment with Single Ton paradigm
 * 
 * @author Michael Sanelli & Nicola Corti
 */
public class SingleTonEnvironment {
	
	/**	Enviroment Object */
	private static Environment env = null;
	
	/** This method return the Environment object.
	 *  If object doesn't exists, a new object will be created,
	 *  otherwise the object will be returned
	 */
	public static synchronized Environment getIstance() {
		if (env == null) env = new Environment();
		return env;
	}

}
