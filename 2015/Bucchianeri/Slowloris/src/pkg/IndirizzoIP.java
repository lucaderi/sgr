package pkg;

/* Classe che descrive un indirizzoIP e quante volte e' stato incontrato. La variabile d'istanza ip
 * memorizza la stringa contente l'ip, la variabile counter permette di contare da 1 in poi.
 */
class IndirizzoIP {

	String ip;
	int counter;
	
	public IndirizzoIP(String p){
		ip = p;
		counter = 1;
	}
	
	public void incrementaContatore(){
		this.counter++;
	}


	@Override
	public boolean equals(Object obj) {
		String paramip = (String) obj;
		if(ip.equals(paramip)) return true;
		else return false;
	}

	@Override
	public String toString() {
		return "IndirizzoIP [ip=" + ip + ", counter=" + counter + "]";
	}
	
}

	