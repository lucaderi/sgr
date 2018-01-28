/**
 * Class Server
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class Server {
	/** Nome del Server */
	private String server;

	/**
	 * Costruttore Server
	 * 
	 * @param server
	 *            Stringa contenente il nome del sito
	 */
	public Server(String server) {
		this.server = server;
	}

	/**
	 * Metodo che ritorna il nome del Server
	 * 
	 * @return Stringa contenente il nome del Server
	 */
	public String getServer() {
		return this.server;
	}
}
