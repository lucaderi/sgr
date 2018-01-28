package detects_attacks;

/**  		  	PROGETTO DI GESTIONE DI RETE 
 *  Rilevazione di uno o più attacchi dato un file di flussi
 *       			    Ambra Buscemi 
 *    			      Matricola: 475947
 *    	 			     Marzo 2015
 */


import java.text.SimpleDateFormat;
import java.util.Date;

public class InfoFlow {
	
	private int N_FLUSSI = 0;
	private int IN_PKTS = 0;
	private int IN_BYTES = 0;  
	private long LAST_SWITCHED = 0; 
	//Costante che indicia il minimo numero di flussi da considerare come un attacco
	private static final int  min_limit_flows_attack = 32000; 
	

	//REQUIRES: tutti i parametri del costruttore devono essere >= 0
	//EFFECTS: restituisce un oggetto di tipo InfoFlow in cui tutti i campi sono inializzati. 
	//Solleva un eccezione di tipo IllegalArgumentException:
	//se almeno uno dei parametri passati è < 0
	public InfoFlow( int n_flussi, int in_pkts, int in_bytes, long last_switched) {
		
		if (n_flussi <0 || in_pkts < 0 || in_bytes < 0 || last_switched < 0){
			throw new IllegalArgumentException("Costruttore Flow_Information: viene passato almeno un parametro < 0");
		}
		
		this.N_FLUSSI = n_flussi;
		this.IN_PKTS = in_pkts;
		this.IN_BYTES = in_bytes;
		this.LAST_SWITCHED = last_switched;	
	}
	
	
	//EFFECTS: restituisce il campo N_FLUSSI
	public int getNumFlussi(){
		return this.N_FLUSSI;
	}
	
	
	//EFFECTS: restituisce il campo IN_PKTS
	public int getNumPkt(){
		return this.IN_PKTS;
	}
	
	
	//EFFECTS: restituisce il campo IN_BYTES
	public int getNumByte(){
		return this.IN_BYTES;
	}
	
	
	//EFFECTS: restituisce il campo LAST_SWITCHED
	public long getLastSwitched(){
		return this.LAST_SWITCHED;	
	}
	
	
	//EFFECTS: restituisce il campo LAST_SWITCHED convertito 
	//nel seguente formato date:  dd-MM-yyyy HH:mm:ss z
	public String getLastSwitched_inDate(){
		Date date = new Date(this.LAST_SWITCHED*1000L); // *1000 serve a convertire i secondi in millisecondi
		SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss z"); // il formato scelto della data
		String formatted_date = sdf.format(date);
		return formatted_date;
	}
	
	
	//REQUIRES: tutti i parametri devono essere >= 0
	//EFFECTS: metodo che somma i parametri passati, in_pkts e in_bytes, 
	//rispettivamente alle variabili d'istanza dell'oggetto this IN_PKTS e
	//IN_BYTES e aggiunge 1 alla variabile d'istanza N_FLUSSI 
	//Solleva un eccezione di tipo IllegalArgumentException:
	//se almeno uno dei parametri passati è < 0
	public void addOneFlow(int in_pkts, int in_bytes){
		
		if (in_pkts < 0 || in_bytes < 0){
			throw new IllegalArgumentException("InfoFlow - addOneFlow: viene passato almeno un parametro < 0");
		}
		
		this.N_FLUSSI += 1;
		this.IN_PKTS += in_pkts;
		this.IN_BYTES += in_bytes;
	}
	
	
	//EFFECTS: metodo che ritorna true se la variabile d'istanza N_FLUSSI
	//dell'oggetto this è >= alla costante min_limit_flows_attack.
	//Ovvero ritorna true se rileva un attacco, altrimenti ritorna false.
	public boolean isAttached(){
		return (this.N_FLUSSI >= min_limit_flows_attack);	
	}
	

}
