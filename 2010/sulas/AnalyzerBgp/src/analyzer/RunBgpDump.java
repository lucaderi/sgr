package analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;


/**
 * Classe che lancia bgpdump (http://www.ris.ripe.net/source/)
 * è un programma scritto in C che
 * 			anallizza i file scaricati da http://data.ris.ripe.net/ 
 * 
 * la classe aggiorna l'archivio RRD precedentemente creato
 * 
 * @requirements: 	RRDTOOL deve essere installato nel OS
 * 					BgpDump deve essere installato nel OS
 * 
 * @author Domenico Sulas
 */



public class RunBgpDump extends Thread {
	private String file;
	private String dir;
	
	// informazioni sui pacchetti letti
	
	private int pac; // numero di pacchetti
	private int nup; // numero di pacchetti "update" 
	private int nke; // numero di pacchetti "keepalive"
	
	private int oth; // numero di pacchetti diversi dalle precedenti
	private int nno; // numero di pacchetti "notify"
	private int nop; // numero di pacchetti "open"
	

	private int upd; // numero di richieste "update"
	private int wit; // numero di richieste "withdraw"
	private int cst; // numero di avvisi "change state"
	private int tdm; //  numero di richieste "table dump"

	private int igp; // numero di pacchetti provenienti dallo stesso AS
	private int egp; // numero di pacchetti provenienti da AS esterni
	private int inc; // numero di pacchetti di cui e' impossibile detterminare la provenienza

	private String AS; // nome del AutonomSystem
	
	// contenitori di informazioni sui pacchetti letti
	private NextHopInfo nhi;
	private OriginInfo ori;
	private AutonomSystem aut;
	
	
	/* costruttori */
	
	/**
	 * @param d directory di lavoro
	 * @param f nome file
	 * @param ni raccoglitore info sui next hop
	 * @param oi raccoglitore info sul origine dei pacchetti
	 * @param au raccoglitore info sugli AS
	 */
	public RunBgpDump(String d, String f, NextHopInfo ni, OriginInfo oi, AutonomSystem au) {
		dir = d;
		file = f;
		nhi = ni;
		ori = oi;
		aut= au;
	}

	/* metodi pubblici */
	
	/**
	 * Analizza l'output generato da bgpdump
	 */
	@Override
	public void run() {

		// resetto le informazioni per ogni pacchetto
		nhi.reset();
		ori.reset();

		try {
			// analizzo il pacchetto appena ricevuto
			Process pr = Runtime.getRuntime().exec("bgpdump " + dir + file);

			InputStream is = pr.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);

			String line = null;
			pac = 0;			upd = 0;			wit = 0;
			nop = 0;			nup = 0;			nke = 0;
			nno = 0;			oth = 0;			igp = 0;
			egp = 0;			inc = 0;			cst= 0;
			tdm= 0;

			String nh = "N/A";

			// esci alla fine del "file"
			while ((line = br.readLine()) != null) {

				// Nota: l'output di pacchetti diversi e' separato da una liea vuota!
				while (line != null && !line.equals("\n")) {

					if (line.startsWith("TYPE:")) {
						// ho trovato un nuov pachetto, TUTTI i pacch iniziano col TIPO
						pac++;
						
						// Controllo il tipo e il sotto tipo del pacchetto
						if (line.endsWith("/Update"))
							nup++;						
						else if (line.endsWith("/Keepalive"))
							nke++;
						else{
							oth++;
							
							if (line.endsWith("/Open"))
								nop++;
							else if (line.endsWith("/Notify"))
								nno++;
							else if( line.contains( "STATE_CHANGE"))
								cst++;
							else if( line.contains( "TABLE_DUMP"))
								tdm++;
							
						}
					}
					else if (line.startsWith("FROM: ")) {
						// Controllo il nome dell AS che ha inviato il pacch
						// FROM: 195.66.224.175 AS13030 
						AS= line.substring( line.lastIndexOf( "S") +1);
						aut.setAs( AS);
					}
					else if (line.startsWith("ORIGIN:")) {
						// controllo l'origine del pacch
						if (line.endsWith("IGP"))		// il pacch e' stato generato nel mio stesso AS 
							igp++;
						else if (line.endsWith("EGP"))	// il pacch e' stato generato da un AS esterno
							egp++;
						else
							inc++;
					}
					else {
						// se il pacch e' un UPDATE conterra l'ind IP, del rooter di next hop, su cui instradare
						// le comunicazioni  NEXT_HOP: 195.66.224.175
						if (line.startsWith("NEXT_HOP:")) {
							String[] tmp = line.split(" ");
							nh = tmp[1];
						}
						// il pacchetto annuncia nuove destinazioni o un cambiamento di percorso
						else if (line.equals("ANNOUNCE")) {
							line = br.readLine();
							while (line != null && line.startsWith(" ")) {
								nhi.setNextHop(nh, true);
								upd++;
								line = br.readLine();
							}
						}
						// il pacchetto annuncia varie rimozzioni
						else if (line != null && line.equals("WITHDRAW")) {
							line = br.readLine();
							while (line != null && line.startsWith(" ")) {
								nhi.setNextHop(nh, false);
								wit++;
								line = br.readLine();
							}
						}
					}

					line = br.readLine();
				}
			}

			ori.set(igp, egp, inc);

			String[] tmp = dir.split("/");			

			// aggiorno l'archivio
			// rrdtool update ./webapps/AnalizeBGP/Data/$dir/statistiche.rrd N:$nPac:$nUpda:$nOpen:$nKeep:$nNoty:$nChan:$nTDum:$updReq:$witReq:$others;
			String script = "sh ./webapps/AnalyzerBgp/Script/AggiornaRRD.sh "
					+tmp[tmp.length - 1] +" " +pac +" " +nup +" " +nop +" " +nke
					+" " +nno +" " +cst +" " +tdm +" " +upd +" " +wit +" " +oth;
			
			
			Runtime.getRuntime().exec(script);
			
			
		} catch (IOException ex) {	}
		
		// cancello il file
		File del= new File( dir + file);
		del.delete();
	}
	
}