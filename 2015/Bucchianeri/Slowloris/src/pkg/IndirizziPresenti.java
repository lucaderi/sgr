package pkg;

import java.util.ArrayList;


/* Un oggetto appartenente a questa classe viene creato dal main all'analisi di ogni minuto, esso
 * premette di rilevare l'indirizzo ip responsabile della maggior parte delle connessioni aperte. 
 * L'array contiene tutti ip diversi tra loro, ed ogni oggetto indirizzoIP ha un contatore 
 * per indicare le connessioni aperte.
 */

public class IndirizziPresenti {
	ArrayList<IndirizzoIP> indirizzi;
	
	public IndirizziPresenti(){
		indirizzi = new ArrayList<IndirizzoIP>();
	}
	
	// Quando aggiungo un nuovo indirizzo ip all'array prima controllo che gia' non esista un oggetto
	// con il solito ip, in questo caso incremento il contatore, altrimenti aggiungo un nuovo
	// oggetto IndirizzoIP.
	public int aggiungi(String ip){
		for(IndirizzoIP iip : indirizzi){
			if(iip.equals(ip)){
				iip.incrementaContatore();
				return 0;
			}
		} 
		indirizzi.add(new IndirizzoIP(ip));
		return 1;
	}
	
	public IndirizzoIP indMaxCouter(){
		int max = 0;
		IndirizzoIP ind = null;
		for(IndirizzoIP p : indirizzi){
			if(p.counter > max){
				ind = p;
				max = p.counter;
			}
		}
		return ind;
	}
}