import java.util.ArrayList;
import java.util.List;

/**
 * Class Client
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class Client {
	/** IP del Client */
	private String client;
	/** Lista dei Server */
	private List<Server> listServer = null;
	/** Bytes della navigazione */
	private Bytes bytes;
	/** Tempo di navigazione */
	private Time time;

	/**
	 * Costruttore Client
	 * 
	 * @param client
	 *            Stringa contenente l'IP del client
	 */
	public Client(String client) {
		this.client = client;
		this.listServer = new ArrayList<Server>();
		this.bytes = new Bytes();
		this.time = new Time();
	}

	/**
	 * Metodo che ritorna l'IP del client
	 * 
	 * @return Stringa contenente l'IP del client
	 */
	public String getClient() {
		return this.client;
	}

	/**
	 * Metodo che controlla l'esistenza del Server nella lista
	 * 
	 * @param server
	 *            Stringa contenente il nome del Server
	 * @return Server (se la ricerca ha esito positivo) altrimenti null
	 */
	public Server searchServer(String server) {
		for (int s = 0; s < listServer.size(); s++) {
			if (listServer.get(s).getServer().compareTo(server) == 0)
				return listServer.get(s);
		}
		return null;
	}

	/**
	 * Metodo che aggiunge un Server alla lista
	 * 
	 * @param server
	 *            Nome del Server
	 */
	public void addServer(String server) {
		listServer.add(new Server(server));
	}

	/**
	 * Metodo che ritorna la lista dei Server visitati dal Client
	 * 
	 * @return List<Server> contenente i Server visitati
	 */
	public List<Server> getListServer() {
		return this.listServer;
	}

	/**
	 * Metodo che ritorna i byte della navigazione
	 * 
	 * @return Bytes della naviagazione
	 */
	public Bytes getBytes() {
		return this.bytes;
	}

	/**
	 * Metodo che ritorna il tempo della navigazione
	 * 
	 * @return Time della navigazione
	 */
	public Time getTime() {
		return this.time;
	}
}
