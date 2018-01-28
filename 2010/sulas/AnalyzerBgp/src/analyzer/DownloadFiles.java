package analyzer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * 
 * Classe che si occupa di ricevere e salvare i file contenenti i pacchetti
 * sniffati che verranno analizzati nella classe RunBgpDump
 * 
 * @requirements: 	RRDTOOL deve essere installato nel OS
 * 					BgpDump deve essere installato nel OS
 * 
 * @throw IllegalArgumentException: Controllare il metodo run() per i dettagli 				
 * 				  
 * @author Domenico Sulas
 */

public class DownloadFiles extends Thread implements Comparable<DownloadFiles> {
	
	// directory usate dalla classe
	private final static String downPath = "./webapps/AnalyzerBgp/Downloads/";
	private final static String dataPath = "./webapps/AnalyzerBgp/Data/";

	// nome dell archivio RRD
	private final static String rrdName = "/statistiche.rrd";

	// script con cui lanciare rrdtool create
	private final static String createScript = "sh ./webapps/AnalyzerBgp/Script/CreaRRD.sh ";

	// nome della sotto directory usata dal thread
	private String workDir;

	// URL del repository dei file usata dal thread
	private String url;

	// informazioni generate dal programma
	private NextHopInfo nhInf;
	private OriginInfo orInf;
	private AutonomSystem asInf;

	// client http per comunicare col repository
	private HttpClient clientHttp;

	// variabile che controlla il ciclo di vita del thread
	private boolean stop;

	

	/* costruttori */

	/**
	 * 
	 * Costruttore
	 * 
	 * @param u
	 *            URL usata dal thread
	 * @param n
	 *            calsse in cui salvare le informazioni sui next hop piu usati
	 * @param o
	 *            calsse in cui salvare le informazioni sugli AS maggiormente
	 *            attivi
	 */
	public DownloadFiles(String u, NextHopInfo n, OriginInfo o, AutonomSystem a) {
		if (!u.endsWith("/"))
			url = u.concat("/");
		else
			url = u;
		
		nhInf = n;
		orInf = o;
		asInf = a;

		stop = false;

		// ricavo la directori in cui lavorare
		String[] tmp = u.split("/");
		workDir = tmp[tmp.length - 1];

		// se le sotto directory non esistono le creo
		File dataDir = new File( dataPath + workDir);
		if (!dataDir.exists()) {
			dataDir.mkdir();

			File downDir = new File( downPath + workDir);
			downDir.mkdir();
		}

		// creo un nuovo client
		clientHttp = new DefaultHttpClient();
		setName(workDir);
		
		// permetto al thread di sollevare eccezioni
		setDefaultUncaughtExceptionHandler( new ThreadException());

	}

	/**
	 *  Costruttore "temporaneo" usabile per i confronti
	 *  
	 * @param u
	 * 				l'url del repository
	 */
	public DownloadFiles(String u) {
		if (!u.endsWith("/"))
			url = u.concat("/");
		else
			url = u;
	}
	
	public DownloadFiles(){
		
	}

	
	
	
	/* metodi per passare informazioni ad una pagina jsp */
	
	// ritorna il contenitore di infoprmazioni sui next hop
	public NextHopInfo getNextHop() {
		return nhInf;
	}

	// ritorna il contenitore di infoprmazioni sulle origini dei pacchetti BGP 
	public OriginInfo getOrigin() {
		return orInf;
	}

	// ritorna il contenitore di infoprmazioni sugli AS
	public AutonomSystem getAS() {
		return asInf;
	}

	// // ritorna l url del repository
	public String getUrl() {
		return url;
	}

	/* metodi di confronto */

	/**
	 * due DownloadFiles sono identici SE e SOLO SE contengono la stessa url
	 */
	@Override
	public int compareTo(DownloadFiles arg0) {
		return this.url.compareTo(arg0.url);
	}

	@Override
	public boolean equals(Object arg0) {
		try {
			if (this.compareTo((DownloadFiles) arg0) == 0)
				return true;
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	/* metodi per la gestione del ciclo di vita del thread */

	@Override
	public void interrupt() {
		stop = true;
	}
	

	@Override
	/**
	 *  @throw IllegalArgumentException
	 * 		NOTA	il Thread puo' sollevare principalmente 2 "sotto tipi" di eccezzione distinguibili 
	 * 				in  base al messaggio d'errore trasportato
	 * 
	 * 		- IO exception:
	 *			nel caso si verifichino errori durante l'uso degli script contenenti i comandi RRD
	 * 			nel caso ci siano problemi durante la scrittura dei file ottenuti dal repository
	 * 			nel caso ci siano problemi durante l'esecuzione del probramma BgpDump
	 * 
	 * 		- Comunication exception:
	 * 			nel caso ci siano problemi in fase di connessione col repository
	 * 			nel caso ci siano problemi durante il trasferimento del File	   
	 */
	public void run() {
		// se NON esiste creo l'archivio RRD
		if (!(new File(dataPath + workDir + rrdName)).exists()) {
			try {
				Runtime.getRuntime().exec(createScript + workDir);
			} catch (IOException ex) {				
				throw new IllegalArgumentException( workDir+ " IO exception, RRD problem (create)");
			}
		}

		System.out.println("\n$ " + workDir + " started!");

		// il thread continua a girare FINCHE NON viene chiamato il metodo interrupt()
		while (!stop) {
			String[] oraFile = this.getDate();

			// http://data.ris.ripe.net/rrc00/ + 2010.06/ + updates. + 20100630+ . + 1640 + .gz
			String richiesta = url + oraFile[0] + "/";
			String fileName = "updates." + oraFile[1] + "." + oraFile[2] + ".gz";

			boolean creato = false;			
			try {
				
				creato= downloadFile(richiesta, fileName);
			} catch (ClientProtocolException e) {
				e.printStackTrace();
				throw new IllegalArgumentException( workDir+" Comunication exception");				
			} catch (IOException e) {
				e.printStackTrace();
				throw new IllegalArgumentException( workDir+" IO exception, File IO probelm");
			}

			
			if( creato== false){
				System.out.println( workDir+" Comunication exception: can't download "+fileName);
				// il server e' in ritardo..
				try {
					sleep( 60000);
				} catch ( InterruptedException ex) {}
			}
			else{
				RunBgpDump rbd= new RunBgpDump( downPath + workDir +"/", fileName, nhInf, orInf, asInf);
				rbd.start();
			
				// disegno il grafo
				try {
					Runtime.getRuntime().exec("sh ./webapps/AnalyzerBgp/Script/DisegnaRRD.sh "+ workDir);
				} catch (IOException ex) {				
					throw new IllegalArgumentException( workDir+ " IO exception RRD problem (graph)");
				}
			
				// attendo aggiornamento sito
				try {
					sleep( 60000 * 5);
				} catch ( InterruptedException ex) {}
			}
		}

		clientHttp.getConnectionManager().shutdown();
		System.out.println("\n$ " + workDir + " stopped!");

	}

	/* metodi privati */

	/**
	 * 
	 * Converte un numero rapresentante un giorno/mese in una stringa gg/mm
	 * in pratica converte un numero in una Stringa di due cifle, aggiungendo lo 0 nel caso sia necessario
	 * 
	 * @param n
	 *           numero da convertire
	 *            
	 * @return Stringa contenente un numero di 2 cifre
	 */
	private String convertToString(int n) {

		if (n < 10)
			return "0" + n;
		else
			return "" + n;
	}

	/**
	 * 
	 * Scarica il file url/name da url
	 * 
	 * @param name
	 *            nome del file da scaricare
	 *            
	 * @return true se il file e' stato correttamente scritto sul disco
	 * 
	 * @throws IOException
	 * @throws ClientProtocolException
	 */
	private boolean downloadFile(String u, String name)	throws ClientProtocolException, IOException {
		File doc = new File(downPath + workDir + "/" + name);

		
		// richiedo il file
		HttpGet get = new HttpGet(u + name);
		HttpResponse r = clientHttp.execute(get);

		// controllo la risposta del server
		int status = r.getStatusLine().getStatusCode();
			
		if (status < 200 || status > 300) {
			clientHttp.getConnectionManager().closeExpiredConnections();
			return false;
		}

		HttpEntity fe = r.getEntity();

		// copio il file
		if( !doc.createNewFile()){
			return false;
		}

		InputStream fin = fe.getContent();
		FileOutputStream fout = new FileOutputStream(doc);

		byte[] buf = new byte[250];
		int letti = 0;
		while ((letti = fin.read(buf)) != -1) {
			fout.write(buf, 0, letti);
			fout.flush();
		}

		fin.close();
		fout.close();

		clientHttp.getConnectionManager().closeExpiredConnections();
			
		return true;
	}

		

	/**
	 * Genera la data "odierna a GMT-2"
	 *	
	 * 
	 * @return : data[] dove
	 * 		data[0]= yyyy.mm/ 
	 * 		data[1]= yyymmdd 
	 * 		data[2]= hhmm
	 */
	private String[] getDate() {
		String[] data = new String[3];

		GregorianCalendar gc = new GregorianCalendar(TimeZone.getTimeZone("GMT-2:00"));

		// ottengo anno mese giorno
		int year = gc.get(Calendar.YEAR); 			// anno corrente
		int mont = gc.get(Calendar.MONTH) + 1; 		// mese corrente (parte a contare da 0)
		int day = gc.get(Calendar.DAY_OF_MONTH); 	// giorno corrente

		// aggiorno giorno e ora
		int ora = gc.get(Calendar.HOUR_OF_DAY);
		int min = gc.get(Calendar.MINUTE);
		
		/* 	
		 * prelevo i file di 3 ora fa per evitare grafici con dei "buchi"
		 * - in quanto il server uppa i file con almeno 2 ore e 5 min ritardo
		 * - gli orari server/localhost possono non essere sincronizzati..
		 */
		
		// sistemo i minuti (ottengo un multiplo di 5)		
		min = (min - (min %5));		
				
		String mm = convertToString(mont);
		String dd = convertToString(day);
		String hh = convertToString(ora);
		String mi = convertToString(min);

		data[0] = year + "." + mm;
		data[1] = year + mm + dd;
		data[2] = hh + mi;

		return data;
	}

}