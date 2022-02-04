package org.snmptweet.snmptrap;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.Vector;

import org.snmptweet.conf.Environment;
import org.snmptweet.conf.SingleTonEnvironment;

import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoader;
import net.percederberg.mibble.MibLoaderException;
import net.percederberg.mibble.MibValueSymbol;
import snmp.SNMPObjectIdentifier;

/**
 * This file allows you to load several MIB files, and convert various OID format understandable
 * @author Nicola Corti & Michael Sanelli
 *
 */
public class MibParser {
	/** This contain the structure of all loaded mibs */
	private Vector<Mib> mibs;
	/** This contain the the configuration of the server */
	private Environment env;
	
	/**
	 * Constructor of MibParser Class
	 * @param dir The directory where we have the Mib file
	 */
	public MibParser(File dir) {
		super();
		this.env = SingleTonEnvironment.getIstance();
		loadMibs(dir);
	}
	
	/**
	 * This method convert an OID to a understandable string
	 * @param oid The ObjectIdentifier that we want to convert
	 * @param extended if true the method return a very verbose conversion of the OID
	 * @return The string that identify the OID
	 */
	public String convertOid(SNMPObjectIdentifier oid, boolean extended) {
		Iterator<Mib> iterator = this.mibs.iterator();
		
		Mib mibtmp = null;
		String retv = null;
		MibValueSymbol temp = null;
		
		while (iterator.hasNext() && retv == null) {
		
			mibtmp = iterator.next();
			temp = mibtmp.getSymbolByValue(oid.toString());
			
			/* if Oid is not found, temp is null */
			if (temp instanceof MibValueSymbol) {
				retv = "";
				if (extended)
					/* Used for composing extendend Strings */
					retv += temp.getMib().getName() + "::";
				retv += temp.getName();
				break;
			}
		}
		
		if (retv != null)
			return retv;
		else
			return oid.toString();
	}
	
	
	/**
	 * Try to load all mibs from the directory.
	 * @param dir The directory where the user store him mibs file.
	 */
	private void loadMibs(File dir) {
		
		File[] files = dir.listFiles();
		MibLoader loader = new MibLoader();
		loader.addDir(dir.getAbsoluteFile());
		
		Vector<Mib> loaded = new Vector<Mib>();
		
		for (File f: files) {
			try {
				loaded.add( loader.load(f) );
			} catch (IOException e) {
				this.env.printLogFile("Failed to open " + f.getName() +": " + e.getMessage(), true);
				e.printStackTrace();
			} catch (MibLoaderException e) {
				this.env.printLogFile("Failed to parse " + f.getName() +": " + e.getMessage(), true);
			}
		}
		this.env.printLogFile("N° Mibs in the directory: " + files.length + " Caricati :" + loaded.size(), false);
		this.mibs = loaded;
	}
}
