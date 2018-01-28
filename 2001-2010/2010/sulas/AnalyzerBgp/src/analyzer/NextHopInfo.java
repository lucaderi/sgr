package analyzer;

import java.util.Vector;

/**
 * 
 * Classe per immagazzinare le informazioni sui next hop    
 *  
 *   @author Domenico Sulas
 */

public class NextHopInfo {	
	private Vector<NextHop> nHop;
	
	/* costruttore */
	
	public NextHopInfo(){		
		nHop= new Vector<NextHop>();
	}
	
	/* metodi pubblici */
	
	/**
	 * resetta tutto
	 */
	public void reset(){		
		nHop.clear();
	}
	
	/**
	 * 
	 * aggiunge o aggiorna le informazioni per un next hop
	 * 
	 * @param ip  : indirizzo ip del rooter di next hop
	 * @param upd : indica se il metodo viene chiamato dopo aver ricevuto un update o un withdraw
	 */
	public void setNextHop( String ip, boolean upd){
		NextHop tmp= new NextHop( ip);
		
		synchronized( nHop){
			int i= nHop.indexOf( tmp);
		
			if( i== -1){
				tmp.setUse( 1);
				nHop.add( tmp);
			}
			else{
				tmp= nHop.elementAt( i);
				if( upd)
					tmp.setUse( 1);
				else
					tmp.setUse( -1);
			}
		}
	}
	
	/**
	 * cerca i primi 3 next hop per cui passano il magior numero di rotte
	 *  
	 * @return: i 3 next hop piu' "usati"
	 */
	public String[] getBest(){
		String[] best= new String[] {"N/A_0", "N/A_0", "N/A_0"};
		int max= 0;
		int suc= 0;
		int las= 0;
		
		synchronized( nHop){
			if( !nHop.isEmpty()){
				for( int i = 0; i< nHop.size(); i++){
					
					int use= nHop.elementAt( i).getUse();
					if( use > max){
						best[2]= best[1];
						best[1]= best[0];
						best[0]= nHop.elementAt( i).toString();
						max= use;
					}
					else if( use> 0){
						if( use > suc){
							best[2]= best[1];
							best[1]= nHop.elementAt( i).toString();
							suc= use;
						}
						else if( use > las){
							best[2]= nHop.elementAt( i).toString();
							las= use;
						}
						else if( best[1].equals( "N/A_0"))
							best[1]= nHop.elementAt( i).toString();
						else if(best[2].equals( "N/A_0"))
							best[2]= nHop.elementAt( i).toString();
					}
				}
			}
		}
		
		return best;
	}
	
	
	/* classe privata */
	
	/**
	 * classe che rappresenta un router (in particolare quello di next hop)
	 */
	private class NextHop implements Comparable<NextHop>{
		String ip;
		int use;
		
		public NextHop( String i){
			ip= i;
			use= 0;
		}
		
		public void setUse( int i){
			use= use+i;
		}
		
		public int getUse(){
			return use;
		}
		
		@Override
		public boolean equals( Object o){
			
			if( this.ip.equals( ((NextHop)o).ip))
				return true;
			else
				return false;
		}

		@Override
		public int compareTo(NextHop arg0) {
			return this.ip.compareTo( arg0.ip );
		}
		
		public String toString(){
			return ip+"_"+use;
		}
		
	}
	
}
