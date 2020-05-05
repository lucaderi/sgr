package reti;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;


import org.rrd4j.core.Util;

class Nodo {
    int prot;
    String name_protocol = null;
    int occ = 0;
    int percentuale = 3;
    Nodo next = null;
}

public class ListaConcatenata {
	private Nodo start;
    private int size;
    private int occorrenzetotali;
    private int soglia = 0;
    private long data;
    private String filename ="";

    public ListaConcatenata() {
        size = 0;
        occorrenzetotali = 0; 
        start = null;
    }

	public void setData(int year , int month , int date , int hourOfDay, int minute){
		data = Util.getTimestamp(year, month, date, hourOfDay, minute);
    	//System.out.println(data.getTime().getTime());
    }
	public long getData(){
		return data;
	}
    public int addNameProtocol(String fileprotocol){
    	BufferedReader in = null;
    	String Riga = null;
		try {
			in = new BufferedReader(new FileReader(fileprotocol));
		}catch (FileNotFoundException e1) {
			return -1;
		}
    	try {
    		Nodo iter = start;
    		int i = 0;
			while(in.ready()){
				Riga = in.readLine();
			    Nodo nuovo = new Nodo();
			    nuovo.name_protocol = Riga;
			    nuovo.prot = i;
			    i++;
			    if( start == null){
			        start = nuovo;
			        iter = start;
			    }else{
			    	iter.next = nuovo;
			    	iter = iter.next;
			    }
			    size++;
			    
			}
		} catch (IOException e) {
			return -1;
		}
		return 0;
    }
    public void add(int protocollo) {
    	if (start.prot <= protocollo){
            Nodo iter = null;
            for(iter = start; iter.next != null && iter.next.prot <= protocollo; iter = iter.next);
            
    		if(iter.prot == protocollo){
    			iter.occ++;	
    		}
            	
    	}else{
    		if(start.prot == protocollo){
    			start.occ++;	
    		}else{
    			System.out.println("Non è stato possibile inserire il protocollo con indice:" + protocollo + ", poichè non presente nella lista dei protocolli, cercare un aggiornamento software");
    		}
    		
    	}
        
		occorrenzetotali++;
    }

    
    public void add(String protocollo) {
    	if (start.name_protocol.compareTo(protocollo)!=0){
            Nodo iter = start;
            for(iter = start; iter != null && iter.name_protocol.compareTo(protocollo) != 0 ; iter = iter.next);
            
        	if(iter!= null && iter.name_protocol.compareTo(protocollo) == 0){
        			iter.occ++;
        			occorrenzetotali++;
        		}else{
        			System.out.println("Non è stato possibile inserire il protocollo: " + protocollo + ", poichè non presente nella lista dei protocolli, cercare un aggiornamento software");
        		}
    	}else{
    			start.occ++;	
    			occorrenzetotali++;
    	}

    }

    public void remove(int protocollo) {
        if(start!=null && start.prot==protocollo) {
        	occorrenzetotali = occorrenzetotali - start.occ;
            start = start.next;
            size--;
            return;
        }
        if (start!= null){
	        Nodo current = start.next;
	        Nodo previous = start;
	        for(; current!=null; current=current.next) {
	            if(current.prot == protocollo) {
	            	occorrenzetotali = occorrenzetotali - current.occ;
	                previous.next = current.next;
	                current = previous;
	                size--;
	                
	                return;
	            } else {
	                previous = previous.next;
	            }
	        }
        }else{
        	return;
        }
    }

    public boolean isEmpty() {
        return size==0;
    }

    public int size() {
        return size;
    }

    public int occorrenzetotali() {
        return occorrenzetotali;
    }
    
    //Ritorna null se l'indice è fuori dalla lista altrimenti ritorna il nodo 
    public Nodo getNode(int n){
    	int i = 0;
        for(Nodo iter = start; iter != null; iter = iter.next , i++){
            if (i == n){
            	return iter;
            }
        }
		return null;
    }
    
    public void calcolapercentuali(){
    	//this.remove(0);
        for(Nodo iter = start; iter != null; iter = iter.next){
            iter.percentuale = (int) (Math.round((((double)iter.occ) / occorrenzetotali)*100)) ;
            if (iter.percentuale  < soglia || iter.occ == 0) {
            	occorrenzetotali = occorrenzetotali - iter.occ;
            	this.remove(iter.prot);
            }
        	}
        if (soglia != 0 ){
	        for(Nodo iter = start; iter != null; iter = iter.next){
	            iter.percentuale = (int) (Math.round((((double)iter.occ) / occorrenzetotali)*100)) ;
	        }
        }
    }
    
    
    public boolean contains(int n) {
        for(Nodo iter = start; iter!=null; iter = iter.next)
            if (iter.prot==n) return true;
        return false;
    }

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public String getFilename() {
		return filename;
	}

}