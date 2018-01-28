package analyzer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;

/**
 * 
 * classe per gestire il file contenente gli indirizzi dei repository
 *
 *	@author Domenico Sulas
 */

public class Repository implements Serializable {
	
	private static final long serialVersionUID = 1L;
	public String name;
	
	
	/* Costruttore */
	
	public Repository(){
		name= "./webapps/AnalyzerBgp/Data/SitiNoti.txt";
	}
	
	
	
	/* metodi pubblici */
	
	/**
	 * 
	 * legge il contenuto del file
	 * 
	 * @return : una stringa contenente tutti i repository noti
	 * 			 gia' formattati per una select html
	 */
	public synchronized String createHtml(){
		String out= "";
		
		try {
			BufferedReader read= new BufferedReader( new FileReader(name));
			String line;			

			while( ( line= read.readLine())!= null)
				out+="<option value='"+line+"'>"+line+"</option>";
			read.close();
		} catch (IOException e) { out= "";}
				
		return out;
	}
	
	/**
	 * 
	 * legge il contenuto del file
	 * 
	 * @return : una stringa contenente tutti i repository separati da " "
	 */
	public synchronized String load(){
		String out= "";
		
		try {
			BufferedReader read= new BufferedReader( new FileReader( name));
			String line;			

			while( ( line= read.readLine())!= null)
				out+= line+" ";
			
			read.close();
		} catch (IOException e) { out= " ";}
				
		return out;
		
	}
	
	
	/**
	 * 
	 * elimina un repository dal file
	 * 
	 * @param r : riga da eliminare
	 */
	public synchronized void clear( String r){		
		File nuovo= new File( "tmp");
		File vecchio= new File( name);
		
		try {
			BufferedReader read= new BufferedReader( new FileReader( vecchio));
			BufferedWriter write= new BufferedWriter( new FileWriter( nuovo));
			String line;			

			while( ( line= read.readLine())!= null){
				if( !line.equals( r))
					write.write( line+"\n");
			}
			read.close();
			write.close();
			
			vecchio.delete();
			nuovo.renameTo( new File( name));
			
		} catch (IOException e) { }
	}

	
	/**
	 * 
	 * aggiunge un nuovo repository al file
	 * 
	 * @param r la riga da aggiungere
	 */
	public synchronized void add( String r){
		try{
			BufferedWriter write= new BufferedWriter( new FileWriter( name, true));
			write.write( r+"\n");					
			write.close();
		} catch (IOException e) { }
	}
}
