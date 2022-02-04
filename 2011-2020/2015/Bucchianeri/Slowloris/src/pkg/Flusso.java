package pkg;


/* Classe che descrive un flusso. Ha come variabili d'istanza le informazioni piu' importanti prelevate da un flusso.
 * Affinche' siano considerati uguali, due flussi devono avere le prime 4 variabili d'istanza uguali per contenuto.
 */
public class Flusso {
	String srcaddr; // Indirizzo ip sorgente
	String dstaddr; // Indirizzo ip destinazione
	int l4srcport; // Porta sorgente
	int l4dstport; // Porta destinazione
	int npkt; // Numero di pacchetti
	int nbytes; // Numero di byte
	int timefirstpkt; // SysUptime del primo pacchetto del flusso
	int timelastpkt; // SysUptime dell'ultimo pacchetto del flusso
	
	
	public Flusso(String as, String ad, String ps, String pd, String np, String nb, String tfp, String tlp){
		srcaddr = as;
		dstaddr = ad;
		l4srcport = new Integer(ps).intValue();
		l4dstport = new Integer(pd).intValue();		
		npkt = new Integer(np).intValue();
		nbytes = new Integer(nb).intValue();	
		timefirstpkt = new Integer(tfp).intValue();
		timelastpkt = new Integer(tlp).intValue();
	}
	
	public String toString(){
		return "IPV4_SRC_ADDR: " + srcaddr + "  " +
				"IPV4_DST_ADDR: " + dstaddr + "  " +
				"L4_SRC_PORT: " + l4srcport + "  " +
				"L4_DST_PORT: " + l4dstport + "  ";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((dstaddr == null) ? 0 : dstaddr.hashCode());
		result = prime * result + l4dstport;
		result = prime * result + l4srcport;
		result = prime * result + ((srcaddr == null) ? 0 : srcaddr.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Flusso other = (Flusso) obj;
		if (dstaddr == null) {
			if (other.dstaddr != null)
				return false;
		} else if (!dstaddr.equals(other.dstaddr))
			return false;
		if (l4dstport != other.l4dstport)
			return false;
		if (l4srcport != other.l4srcport)
			return false;
		if (srcaddr == null) {
			if (other.srcaddr != null)
				return false;
		} else if (!srcaddr.equals(other.srcaddr))
			return false;
		return true;
	}

	

}

