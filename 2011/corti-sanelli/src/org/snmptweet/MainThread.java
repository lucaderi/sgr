/**
 * SNMP Tweet Main Thread
 * 
 * This file contain the source code of main thread
 * 
 * @author Nicola Corti & Michael Sanelli
 * @year 2011
 *
 */

package org.snmptweet;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.BindException;
import java.util.Properties;

import org.snmptweet.conf.*;

/**
 * Class containing Main thread code.
 */
public class MainThread {
	
	/**
	 * Static string that contain Config File name.
	 */
	private static String ConfigFile = "./snmptweet.conf";
	
	/**
	 * Boolean flag used for checking if default mode is used.
	 */
	private static boolean default_mode = false; 
	
	public static void main(String[] args) {
		
		System.out.println("Welcome to SNMPTwitter");

		
		/*
		 * Loading config settings from 'ConfigFile'
		 * If occour an I/O error, the execution end.
		 */
		Properties config = new Properties();
		try {
			config.load(new FileInputStream(ConfigFile));
		} catch (FileNotFoundException e1) {
			System.out.println("Configuration file " + ConfigFile + " not found! \n Starting with default mode");
			default_mode = true;
		} catch (IOException e1) {
			System.out.println("Error reading " + ConfigFile + " file");
			System.exit(5);
		}
		
		/* Loading execution enviroment,
		 * log files and mib folder.
		 */
		Environment mainenv = SingleTonEnvironment.getIstance();

		if (!default_mode) loadProperties(config);
				
		/* Trying to initialiaze the environment
		 */
		try{
			mainenv.initialize();
		} catch (BindException e) {
			/* Entered port is unavailable */
			mainenv.printLogFile("Port " + mainenv.getPort() + " isn't available. Check permission", true);
			System.exit(91);
		} catch (IOException e) {
			/* Log file or Mib Dir I/O Exception */
			mainenv.printLogFile("I/O Error" + e.getMessage(), true);
			System.exit(5);
		}
		
		
		/* TODO Da fare la stampa dell'ambiente */
		mainenv.printLogFile("=== SNMPTwitter SUCCESSFULLY INITIALIZED ===\n", false);
    	
		
		/* Creating and starting Listener and Sender Threads
		 */
    	ListenerThread listenThread = new ListenerThread();
    	TweetThread tweetThread = new TweetThread();
    	
    	listenThread.start();
    	tweetThread.start();
    	try {
    		/* TODO
    		 * Problema con la join sul listener thread
    		 */
    		listenThread.join();
    		tweetThread.join();
    	}
    	catch (InterruptedException e){
    		listenThread.interrupt();
    		tweetThread.interrupt();
    	}

	}
	
	
	/**
	 * loadProperties subroutine load config information from a config file
	 * and update the enviroment as needed.
	 * 
	 * This subroutine also found all associations between Users and IPs and
	 * store them inside mainevn.
	 * 
	 * @param config Already loaded config file.
	 */
	private static void loadProperties (Properties config){
		
		String user = null;
		String ip = null;
		Environment mainenv = SingleTonEnvironment.getIstance();
		
		/* If property LOG_FILE is not found in config file,
		 * method getProperty returns null.
		 * If LogFile is set to null, there won't be no log files.
		 */

		mainenv.setLogfile(config.getProperty("LOG_FILE"));
		
		String temp = null;
		
		temp = config.getProperty("MIB_DIR");
		if (temp != null)
			mainenv.setMibDir(temp);
		
		temp = config.getProperty("PORT");
		if (temp != null)
			mainenv.setPort((int) Integer.parseInt(temp));
		
		temp = config.getProperty("PRIVATE");
		if (temp != null)
			mainenv.setPrivateMode( Boolean.parseBoolean(temp) );
		
		/* Loading USER-IP association from config file.
		 */
		
		int i = 1;
		while ( ((user = config.getProperty("USER"+i)) != null) && ((ip=config.getProperty("IP"+i)) != null) ) {
			mainenv.setAssociation(ip, user);
			i++;
		}
		
		if (i == 1 && mainenv.getPrivateMode() == true)
			mainenv.printLogFile("CONFIGURATION ERROR! - Private mode and no user association found", true);
	}

}
 