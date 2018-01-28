package analyzer;

import java.util.Vector;

/**
 * Classe che immagazzina le informazioni sugli AS
 * 
 *  @author Domenico Sulas
 */
public class AutonomSystem {
	
	private Vector<AS> asNoti;
	
	/* costruttore */
	public AutonomSystem(){
		asNoti= new Vector<AS>();
	}
	
	/**
	 * aggiorna le informazioni su un AS
	 * 
	 * @param as: identificativo di un AS
	 */
	public void setAs( String as){
		AS tmp= new AS( as);		
		
		synchronized( asNoti){
			int i= asNoti.indexOf( tmp);
			
			if( i== -1){
				tmp.setAnnunce();
				asNoti.add( tmp);				
			}
			else{
				tmp= asNoti.elementAt( i);
				tmp.setAnnunce();
			}
		}
	}
	
	
	/**
	 * cerca i primi 3 AS che hanno inviato il maggior numero di annunci
	 *  
	 * @return: i 3 AS piu' attivi
	 */
	public String[] getBest(){
		String[] best= new String[] {"N/A_0", "N/A_0", "N/A_0"};
		int max= 0;
		int suc= 0;
		int las= 0;
		
		synchronized( asNoti){
			if( !asNoti.isEmpty()){				
				for( int i = 0; i< asNoti.size(); i++){
					
					int use = asNoti.elementAt( i).getAnnunce();
					if( use > max){
						max= use;
						best[2]= best[1];
						best[1]= best[0];
						best[0]= asNoti.elementAt( i).toString();
					}
					else if( use> 0){
						if( use > suc){
							best[2]= best[1];
							best[1]= asNoti.elementAt( i).toString();
							suc= use;
						}
						else if( use > las){
							best[2]= asNoti.elementAt( i).toString();
							las= use;
						}
						else if( best[1].equals( "N/A_0"))
							best[1]= asNoti.elementAt( i).toString();
						else if(best[2].equals( "N/A_0"))
							best[2]= asNoti.elementAt( i).toString();
					}
				}
			}
		}		
		return best;
	}
	
	/* classe privata */
	
	private class AS implements Comparable<AS>{
		private String as;
		private int nAnnunci;
		
		public AS( String a){
			as= a;
			nAnnunci= 0;			
		}
		
		public void setAnnunce(){
			nAnnunci++;
		}
		
		public int getAnnunce(){
			return nAnnunci;
		}
		
		
		@Override
		public boolean equals( Object o){
			
			if( this.as.equals( ((AS)o).as))
				return true;
			else
				return false;
		}

		@Override
		public int compareTo( AS arg0) {
			return this.as.compareTo( arg0.as );
		}
		
		public String toString(){
			return as+"_"+nAnnunci;
		}
	}

}
