package pkg;

/* Classe che descrive una connessione tra due macchine tramite TCP. E' descritta da due flussi, in quanto monodirezionali.
 * Al momento della creazione della connessione ho solo il flusso A a descriverla, durante lo scorrimento del file
 * contenente i flussi controllo che non esista gia' una connessione con tali IP e PORTE; in caso esista, significa
 * che ho trovato il flusso monodirezionale che rappresenta la direzione opposta e lo salvo nella variabili d'istanza B.
 *
 * La classe, oltre che memorizzare i due flussi, mantiene, in altre variabili d'istanza, il numero di pacchetti scambiato,
 * il numero di byte scambiato, il tempo di inizio del flusso e il tempo di fine. Inoltre ricorda se un flusso e' stato 
 * visto aprirsi, tramite un syn, o chiudersi, tramite un fin o reset.
 */
public class Connessione {
	Flusso A;
	Flusso B;
	boolean aperta;
	boolean chiusa;
	boolean fininviato;
	boolean syninviato;
	int totpacchetti;
	int totbytes;
	int tempoinizio;
	int tempofine;
	
	public Connessione(Flusso f){
		A = f; aperta = false; chiusa = false; B = null;
		this.fininviato = false;
		this.syninviato = false;
		this.totpacchetti = 0;
		this.totbytes = 0;
		this.tempoinizio = 0;
		this.tempofine = 0;
	}
	
	
	// Metodo che permette di aggiungere il flusso in direzione opposta
	public void add(Flusso f){
		B = f; aperta = true;
	}
	
	/* Metodo che indica se un flusso appartiene alla connessione.
	 * Restituisce:
	 * 0 : il flusso non appartiene alla connessione
	 * 1 : il flusso appartiene alla connessione sul lato A
	 * 2 : il flusso appartiene alla connessone, ma dal lato B
	 * 
	 */
	public int isIn(Flusso f){
		// Devo dire se questo flusso fa parte di questa connessione o no.
		if(f.srcaddr.equals(A.srcaddr) && f.dstaddr.equals(A.dstaddr) && f.l4dstport == A.l4dstport && f.l4srcport == A.l4srcport){
			return 1;
		} else if(B!=null){
			if(f.srcaddr.equals(B.srcaddr) && f.dstaddr.equals(B.dstaddr) && f.l4dstport == B.l4dstport && f.l4srcport == B.l4srcport){
				return 2;
			}
		} else if(B==null){
			if(f.srcaddr.equals(A.dstaddr) && f.dstaddr.equals(A.srcaddr) && f.l4dstport == A.l4srcport && f.l4srcport == A.l4dstport){
				return 2;
			}
		} else {
			return 0;
		}
		return 0;
	}


	
	public String toString(){
		int durata = (this.tempofine - this.tempoinizio)+1;
		if(B==null){
			return "A: " + A.toString() + "aperta:" +aperta+ " chiusa:" +chiusa + "\n\ttotpkt:" +totpacchetti +
					" tempo inizio: "+ this.tempoinizio +"\n" ;
		} else {
			return "A: " + A.toString() + 
					"\n\tB: " + B.toString() + "aperta:" +aperta+ " chiusa:" +chiusa+ "\n\ttotpkt:" +totpacchetti + " totbytes:"
					+ totbytes +" tempo inizio:"+ this.tempoinizio +" tempo fine:"+ this.tempofine + "  durata connessione(sec):" + durata + "\n";
		}
	}
}
