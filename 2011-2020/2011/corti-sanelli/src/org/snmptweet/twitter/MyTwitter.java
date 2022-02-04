/**
 * MyTwitter
 * 
 * This class is used to interface with twitter.
 * It use the twitter4j library.
 * @author Michael Sanelli & Nicola Corti
 *
 */
package org.snmptweet.twitter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.snmptweet.conf.Environment;
import org.snmptweet.conf.SingleTonEnvironment;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;

public class MyTwitter {
	/** Twitter object used to interface with twitter */
	private Twitter twitter;
	/** Environment used to get execution information */
	private Environment env;
	/** Macro used to define tweet size, needed for message cutting */
	private final int TWEET_SIZE = 135; 
	
	/**
	 * This is the constructor of MyTwitter class
	 */
	public MyTwitter() {
		super();
		this.twitter = null;
		this.env = SingleTonEnvironment.getIstance();
	}

	/**
	 * This method is used for sending message on twitter.
	 * 
	 * If privateMode is true, no public message will be sent, only private messages.
	 * If message is long more than TWEET_SIZE chars, it will be divided into more tweets.
	 * If user is not null, a private message will be sent to specified user.
	 * 
	 * @param user User that will receive private message
	 * @param message Text of message
	 * @param serial Serial number, used to divide message into more tweets
	 * @param privateMode Boolean flag for private mode
	 */
	public void sendUpdate(String user, String message, int serial, Boolean privateMode) {
		
		int i = 1;
		String temp = null;
		
		try {
			if (privateMode != true) {
				if (message.length() > TWEET_SIZE)
				{
					/* If message is too long it will be divided */ 
					while (message.length() > TWEET_SIZE*i)
					{
						/* Serial number is used for separing tweet */
						temp = serial + ": " + message.substring(TWEET_SIZE * i , TWEET_SIZE * (i+1));
						i++;
						this.twitter.updateStatus(temp);
					}
				}
				else
					this.twitter.updateStatus(message);
				this.env.printLogFile("Status updated: Sent trap #" + serial , false);
			}
		} catch (TwitterException e) {
			this.ExceptionHandler(e);
		}		
		
		try {	
			if ( user != null) {
				this.twitter.sendDirectMessage(user, message);
				this.env.printLogFile("Private message: Sent trap #" + serial + " to: " + user , false);
			}
		} catch (TwitterException e) {
			this.ExceptionHandler(e);
		}	
		
	}
	
	
	/**
	 * This method is used to login on twitter.
	 * 
	 * If user has already logged in past, the authentication will be automatic.
	 * Otherwise, a URL will be shown to user for twitter authorization.
	 * 
	 * If user has revoked authorization to SNMP Tweet, a new authentication will be done.
	 */
	public void handShaker(){
			
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		Twitter twitter = new TwitterFactory().getInstance();
		AccessToken acctoken = null;
		RequestToken reqtoken = null;		
		
		
		/* Try to deserialize KeyContainer Object.
		 * If fails, a new empty KeyContainer Object will be created
		 */
		KeyContainer keys = null;
		try{
			keys = KeyContainer.deSerialize();	
		} catch (Exception e) {
			env.printLogFile("Unable to read from keys.dat, trying to start anyway", true);
			keys = new KeyContainer();
		}
		
		/* User access token keys found.
		 * Veryfing credentials
		 */
		if (keys.isHastoken())
		{
			twitter.setOAuthConsumer(keys.getConsumer(), keys.getConsumersecret());
			acctoken = new AccessToken(keys.getToken(), keys.getTokensecret());
			twitter.setOAuthAccessToken(acctoken);
			
			env.printLogFile("Twitter Keys Found", false);
			try {
				twitter.verifyCredentials();
			} catch (TwitterException e) {
				keys.setHastoken(false);
				env.printLogFile("Old Keys was wrong!", true);
			}			
		}
		

		/* User access token keys not found.
		 * Displaying URL and getting Access Token
		 */
		if (!keys.isHastoken())
		{
			try{
				twitter = new TwitterFactory().getInstance();
				twitter.setOAuthConsumer(keys.getConsumer(), keys.getConsumersecret());
				reqtoken = twitter.getOAuthRequestToken();
	
				System.out.println("Need autorization for send tweet, go on: \n" + reqtoken.getAuthorizationURL() + "\nand press ENTER");
				reader.readLine();
				
				acctoken = twitter.getOAuthAccessToken();
				twitter.verifyCredentials();

			} catch (TwitterException e) {
				ExceptionHandler(e);
			} catch (IOException e) {
				
			}
			
		}
		
		
		/* Credential successfully verified
		 * Serializing Key Container
		 */
		keys.setHastoken(true);
		keys.setToken(acctoken.getToken());
		keys.setTokensecret(acctoken.getTokenSecret());
		try {
			keys.serialize();
		} catch (Exception e2) {
			env.printLogFile("Unable to write files keys.dat. Continuing without saving keys", true);
		}
		
		
		/* Printing out current twitter screen name
		 */
		try {
			env.printLogFile("Writing as: " + twitter.getScreenName(), false);
		} catch (TwitterException e1) {
			ExceptionHandler(e1);
		}		
		
		this.twitter = twitter;
	}

	/** Handler of twitter exception.
	 * 
	 *  This method display information about a twitter exception.
	 *  If there is a credential error, a new handshake will be performed
	 *  If there twitter limitation have been exceeded, execution will be paused for some seconds.
	 * 
	 *  @param e The twitter exception
	 */
	public void ExceptionHandler(TwitterException e) {
			
		env.printLogFile("Twitter ERROR: " + e.getStatusCode(), true);
		if(e.isCausedByNetworkIssue()){
			env.printLogFile("ATTENTION: problem with your network", true);
		}
		if(e.getStatusCode() == 500){
			env.printLogFile("FATAL TWITTER ERROR! Check on net for more information", true);
		}
		if(e.getStatusCode() == 502){
			env.printLogFile("Twitter is Down or being upgraded", true);
		}
		if(e.getStatusCode() == 503){
			env.printLogFile("Twitter servers are OVERLOADED, Try again later", true);	
		}
		if(e.getStatusCode() == 401){
			env.printLogFile("Credential error: retrying handshake", true);
			
			this.handShaker();
		}
		if(e.getStatusCode() == 403){
			env.printLogFile("Message Refused, maybe it's too long (over 140 chars)", true);
		}
		if(e.exceededRateLimitation()){
			env.printLogFile("Twitter API Rate exceeded, going to sleep for " + e.getRetryAfter(), true);
			try {
				Thread.sleep(e.getRetryAfter()*1000);
			} catch (InterruptedException e1) {
			}
		}
	}
}
