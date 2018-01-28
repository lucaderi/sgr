import RoundRobinDB.*;
import java.io.*;

public class TestRRD2 {
    public static void main(String[] args) throws IOException{
    	RecordAttribute[] RS = new RecordAttribute[1];
    	RS[0] = new RecordAttribute("Lettere", 10);
    	
    	DBStructure DBS = null;
    	try{DBS = new DBStructure("lettere2", 5, 2, 12, 1, RS);
    	}catch(IllegalArgumentException e){System.out.println("ERRORE DBS"); return;}	
    
    	RoundRobinDB RRD = null;
    	try{RRD = new RoundRobinDB(DBS);
    	}catch(IOException e){System.out.println("ERRORE RRD"); return;}
    	
    	String[] lettere = {"A","B","C"};
    	long[] tempiSleep = {0,3,6};
    	
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
    	
    	Object[][] select = RRD.select("lettere2",15);
    	
    	for(int i = 0; i < select.length; i++){
    		System.out.println((String) select[i][0]);
    	}
    	
    	RRD.close();
    }
}