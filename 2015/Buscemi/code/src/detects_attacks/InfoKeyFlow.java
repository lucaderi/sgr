package detects_attacks;

/**  		  	PROGETTO DI GESTIONE DI RETE 
 *  Rilevazione di uno o più attacchi dato un file di flussi
 *       			    Ambra Buscemi 
 *    			      Matricola: 475947
 *    	 			     Marzo 2015
 */

public class InfoKeyFlow {
	
	private String IPV4_DST_ADDR = null;
	private int L4_DST_PORT = 0;
	private int PROTOCOL = 0;
	
	
	//REQUIRES: tutti i parametri del costruttore devono essere diversi da null o >= 0
	//EFFECTS: restituisce un oggetto di tipo InfoKeyFlow in cui tutti i campi sono inializzati. 
	//Solleva un eccezione di tipo IllegalArgumentException:
	//se il parametro ipv4_dest è uguale a null o se viene passato un valore di dest_port o un
	//valore di protocol < 0
	public InfoKeyFlow( String ipv4_dest, int dst_port, int protocol){
		
		if ( ipv4_dest == null || dst_port < 0 || protocol < 0){
			throw new IllegalArgumentException("Costruttore Point_Attack_Information: viene passato almeno un parametro < 0 o uguale a null");
		}
		
		this.IPV4_DST_ADDR = ipv4_dest;
		this.L4_DST_PORT = dst_port;
		this.PROTOCOL = protocol;
	}
	
	
	//EFFECTS: restituisce il campo IPV4_DST_ADDR
	public String getIPv4Dest(){
		return this.IPV4_DST_ADDR;
	}
	
	
	//EFFECTS: restituisce il campo L4_DST_PORT
	public int getDstPort(){
		return this.L4_DST_PORT;
	}
	
	
	//EFFECTS: restituisce il campo PROTOCOL
	public int getProtocol(){
		return this.PROTOCOL;
	}
	

	//EFFECTS: metodo hashCode riscritto per operare su 
	//tutte le variabili d'istanda della classe InfoKeyFlow
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((IPV4_DST_ADDR == null) ? 0 : IPV4_DST_ADDR.hashCode());
		result = prime * result + L4_DST_PORT;
		result = prime * result + PROTOCOL;
		return result;
	}

	
	//EFFECTS: metodo equals riscritto per operare su 
	//tutte le variabili d'istanda della classe InfoKeyFlow
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		InfoKeyFlow other = (InfoKeyFlow) obj;
		if (IPV4_DST_ADDR == null) {
			if (other.IPV4_DST_ADDR != null)
				return false;
		} else if (!IPV4_DST_ADDR.equals(other.IPV4_DST_ADDR))
			return false;
		if (L4_DST_PORT != other.L4_DST_PORT)
			return false;
		if (PROTOCOL != other.PROTOCOL)
			return false;
		return true;
	}

	
}
