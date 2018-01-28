/**
 * Class Bytes
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class Bytes {

	private int bytes;

	/**
	 * Costruttore
	 */
	public Bytes() {
		this.bytes = 0;
	}

	/**
	 * Funzione per incrementare i bytes relativi alla navigazione del Client
	 * 
	 * @param bytes
	 */
	public void incrementBytes(int bytes) {
		this.bytes = this.bytes + bytes;
	}

	/**
	 * Metodo che ritorna i bytes totali
	 * 
	 * @return bytes totali della navigazione del client
	 */
	public int getTotalBytes() {
		return this.bytes;
	}
}
