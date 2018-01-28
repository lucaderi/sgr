package pkg;
/* Classe che descrive un oggetto Porta, contiene il numero di porta e un contatore.
 */
public class Porta {

	int p;
	int counter;
	
	public Porta(int p1){
		p = p1;
		counter = 1;
	}
	
	public void incrementaContatore(){
		this.counter++;
	}


	@Override
	public boolean equals(Object obj) {
		Integer paramp = (Integer) obj;
		if(p == paramp.intValue()) return true;
		else return false;
	}

	@Override
	public String toString() {
		return "Porta [porta=" + p + ", counter=" + counter + "]";
	}
	
	
}
