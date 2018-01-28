import java.util.StringTokenizer;

/**
 * Class Linelog
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class LineLOG {
	private String Client, Server, Protocol, Method, URL, HTTPReturnCode,
			number;
	private int Bytes, BeginTime, EndTime;

	/**
	 * Costruttore
	 * 
	 * @param line
	 *            Stringa contenente una line letta dal file di log
	 */
	public LineLOG(String line) {
		StringTokenizer st = new StringTokenizer(line);
		Client = st.nextToken("\t");
		Server = st.nextToken("\t");
		Protocol = st.nextToken("\t");
		Method = st.nextToken("\t");
		URL = st.nextToken("\t");
		HTTPReturnCode = st.nextToken("\t");
		number = st.nextToken("\t");
		while (!number.matches("[0-9]+")) {
			number = st.nextToken("\t");
		}
		Bytes = Integer.parseInt(number);
		BeginTime = Integer.parseInt(st.nextToken("\t"));
		EndTime = Integer.parseInt(st.nextToken());
	}

	/**
	 * Metodo che ritorna il Client letto
	 * 
	 * @return Client
	 */
	public String lineClient() {
		return Client;
	}

	/**
	 * Metodo che ritorna il Server letto
	 * 
	 * @return Server
	 */
	public String lineServer() {
		return Server;
	}

	/**
	 * Metodo che ritorna il Protocol letto
	 * 
	 * @return Protocol
	 */
	public String lineProtocol() {
		return Protocol;
	}

	/**
	 * Metodo che ritorna il Method letto
	 * 
	 * @return Method
	 */
	public String lineMethod() {
		return Method;
	}

	/**
	 * Metodo che ritorna l'URL letto
	 * 
	 * @return URL
	 */
	public String lineURL() {
		return URL;
	}

	/**
	 * Metodo che ritorna l'HTTPReturnCode letto
	 * 
	 * @return HTTPReturnCode
	 */
	public String lineHTTPReturnCode() {
		return HTTPReturnCode;
	}

	/**
	 * Metodo che ritorna il Bytes letto
	 * 
	 * @return Bytes
	 */
	public int lineBytes() {
		return Bytes;
	}

	/**
	 * Metodo che ritorna il BeginTime letto
	 * 
	 * @return BeginTime
	 */
	public int lineBeginTime() {
		return BeginTime;
	}

	/**
	 * Metodo che ritorna l'EndTime letto
	 * 
	 * @return EndTime
	 */
	public int lineEndTime() {
		return EndTime;
	}
}
