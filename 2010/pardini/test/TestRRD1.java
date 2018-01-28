import RoundRobinDB.*;
import java.io.*;

public class TestRRD1 {
    public static void main(String[] args) throws IOException{
    	RecordAttribute[] RS = new RecordAttribute[1];
    	RS[0] = new RecordAttribute("Lettere", 10);
    	
    	DBStructure DBS = null;
    	try{DBS = new DBStructure("lettere", 5, 2, 12, 1, RS);
    	}catch(IllegalArgumentException e){System.out.println("ERRORE DBS"); return;}	
    
    	RoundRobinDB RRD = null;
    	try{RRD = new RoundRobinDB(DBS);
    	}catch(IOException e){System.out.println("ERRORE RRD"); return;}
    	
    	String[] lettere = {"A","B","C","D","E","F"};
    	long[] tempiSleep = {0,8,5,8,10,18};
    	
    	String[][] insert = new String[1][1];
    	
    	insert[0][0]=lettere[0];
    	RRD.insert(insert);
    	
    	for(int i = 1; i < lettere.length; i++){
    		try{
    				Thread.sleep(tempiSleep[i]*1000);
    		}catch(InterruptedException e){ return;}    	
    		insert[0][0]=lettere[i];
    		RRD.insert(insert);    		
    	}
    	
    	Object[][] select = RRD.select("lettere",15);
    	
    	for(int i = 0; i < select.length; i++){
    		System.out.println((String) select[i][0]);
    	}
    	
    	RRD.close();
    	
    	System.out.println("********");
    	
    	RRD = null;
    	try{RRD = new RoundRobinDB("lettere");
    	}catch(IOException e){System.out.println("ERRORE RRD -in Open"); return;}
    	
    	select = RRD.select("lettere",15);
    	
    	for(int i = 0; i < select.length; i++){
    		System.out.println((String) select[i][0]);
    	}
    	
    	System.out.println("---------");
    	
    	String[] lettere2 = {"X","G","H","a","b"};
    	long[] tempiSleep2 = {0,3,6,2,5};
    	
    	insert[0][0]=lettere2[0];
    	RRD.insert(insert);
    	
    	for(int i = 1; i < lettere2.length; i++){
    		try{
    				Thread.sleep(tempiSleep2[i]*1000);
    		}catch(InterruptedException e){ return;}    	
    		insert[0][0]=lettere2[i];
    		RRD.insert(insert);    		
    	}
    	
    	select = RRD.select("lettere",15);
    	
    	for(int i = 0; i < select.length; i++){
    		System.out.println((String) select[i][0]);
    	}
    	
    	RRD.close();
    }  
}