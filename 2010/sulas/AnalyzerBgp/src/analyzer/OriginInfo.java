package analyzer;


/**
 * 
 * classe che immagazzina informazioni sulla provenienza dei pacchetti ricevuti
 * 
 *  @author Domenico Sulas
 */
public class OriginInfo {
	private int igp;	// numero di pacchetti interni (provenienti dallo stesso AS)
	private int egp;	// numero di pacchetti esterni (provenienti da un altro AS)
	private int inc;	// numero di pacchetti interni la cui origine e' incompleta
	
	/* costruttori */
	
	public OriginInfo(){
		igp= 0;
		egp= 0;
		inc= 0;
	}
	
	/* metodi pubblici */
	
	public void reset(){
		igp= 0;
		egp= 0;
		inc= 0;
	}
	
	public void set( int ig, int eg, int in){
		igp+= ig;
		egp+= eg;
		inc+= in;
	}
	
	public int[] get(){
		return new int[] {igp, egp, inc};
	}

}
