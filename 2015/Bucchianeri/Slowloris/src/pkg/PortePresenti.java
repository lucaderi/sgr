package pkg;

import java.util.ArrayList;

/* Un oggetto appartenente a questa classe viene creato dal main all'analisi di ogni minuto, esso
 * premette di rilevare la porta con maggiori connessioni aperte. L'array contiene tutte porte
 * diverse tra loro, ed ogni oggetto Porta ha un contatore per indicare le connessioni aperte
 */

public class PortePresenti {
	ArrayList<Porta> porte; // ArrayList che contiene tutte le porte diverse tra loro utilizzate in ogni minuto
	
	public PortePresenti(){
		porte = new ArrayList<Porta>();
	}
	
	// Quando aggiungo una nuova porta all'array prima controllo che gia' non esista un oggetto
	// con la solita porta, in questo caso incremento il contatore, altrimenti aggiungo un nuovo
	// oggetto Porta.
	public int aggiungi(int pp){
		for(Porta p : porte){
			if(p.p == pp){
				p.incrementaContatore();
				return 0;
			}
		} 
		porte.add(new Porta(pp));
		return 1;
	}
	
	public Porta indMaxCouter(){
		int max = 0;
		Porta po = null;
		for(Porta p : porte){
			if(p.counter > max){
				po = p;
				max = p.counter;
			}
		}
		return po;
	}

}
