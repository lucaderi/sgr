package detects_attacks;


/**  		  	PROGETTO DI GESTIONE DI RETE 
 *  Rilevazione di uno o più attacchi dato un file di flussi
 *       			    Ambra Buscemi 
 *    			      Matricola: 475947
 *    	 			     Marzo 2015
 */



import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Scanner;
import java.util.StringTokenizer;

public class Main_Detects_Attacks {
	
	//an_attack serve per indicare la presenza di attacchi all'interno di un file di flussi:
	//se vale 1: all'interno del file si è riscontrato almeno un attacco
	//se vale 0: all'interno del file non si sono riscontrati attacchi
	private static int an_attack = 0; 	
	private static PrintWriter report_attacks = null;
	private static FileReader file_of_flows = null;

			
	
	public static void main(String[] args) {
		
		FileWriter writer_for_report = null;
		int n_file = args.length;
		
		
		//Controllo quanti file vengono passati da linea di comando.
		//Se passo almeno un file: si esegue il parsing per ogni file passato
		//Se non passo nessun file: mando un messaggio in output e termino
		if (n_file > 0){
			
			//Provo ad aprire (e se non esiste creare) un file dove verranno memorizzati 
			//gli attacchi rilevati da ognuno dei file passati da linea di comando.
			//NOTA: La riesecuzione del programma su file diversi o uguali, comporta comunque
			//la scrittura in append nel medesimo file di report ("Report_Attacks_File.txt")
			try {
				writer_for_report = new FileWriter("Report_Attacks_File.txt", true);
				report_attacks = new PrintWriter (writer_for_report);
			}catch (IOException e){
				System.out.println(e.toString() + "Errore nella creazione del file di Resoconto degli Attacchi");
				return;
			}
	
			
			//try-catch-finally: mi assicura la chiusura del file di output 
			//"Report_Attacks_File.txt" indipendentemente dal modo in cui termina
			//il programma (normalmente o a causa una qualsiasi eccezione)
			try{
				for(int i=0; i<n_file; i++){
					
					an_attack = 0; 
					//Provo ad aprire il file contenuto nella variabile "args[i]"
					//ovvero quello contenente i flussi da analizzare
					try{
						file_of_flows = new FileReader (args[i]);
					}
					catch (FileNotFoundException e){
				    	System.out.println(e.toString() + ": File non trovato");
						return;
					}
	
					//try-catch-finally: mi assicura la chiusura del file di input contenuto
					//"nella variabile "args[i]" indipendentemente dal modo in cui termina
					//il programma (normalmente o a causa una qualsiasi eccezione)
					try{			
						//scrivo nel file di output e su shell il nome del file che sto per analizzare
						//NOTA: il controllo serve solo per una migliore formattazione del file di output
						if (i>0){report_attacks.append("\n\nREPORT DEL FILE: " + args[i]);}
						else{report_attacks.append("REPORT DEL FILE: " + args[i]);}
						System.out.println("REPORT DEL FILE: " + args[i]);
	
						//Fulcro centrale di tutto il main: è il metodo parser che 
						//fa il vero lavoro di parsing e successiva generazione dei report
						parser();
	
						}catch (RuntimeException e){
							System.out.println(e.toString());
							return;
						}finally{
							
							try{file_of_flows.close();
							}catch (IOException e){
								System.out.println(e.toString() + "Errore nella chiusura del file");
								return;
							}
						}
					}		
				}catch(RuntimeException e){
					System.out.println(e.toString());
					return;
				}finally{
					report_attacks.close();
				}    	
		}
		else{
			System.out.println("Per l'esecuzione del programma bisogna fornire un file di flussi (ben formattato) da analizzare");
			return;
		}
		
	}

	
	
	
	//EFFECTS: metodo che analizza il file gestito dalla variabile statica "file_of_flows",
	//e genera un report al secondo, indicando se è avvenuto o no un attacco. 
	//In caso di attacco avvenuto, il report viene scritto sia sulla shell
	//sia sul file gestito dalla variabile statica "report_attacks". 
	//MODIFIES: modifica i parametri an_attack, e il file di report_attacks.
	private static void parser(){
		
		Hashtable<InfoKeyFlow, InfoFlow > table_of_flow_analysis = null; 
		Scanner in = null;
		int n_field = 0; //variabile utilizzata per contare le sottostringhe di ogni riga del file
		boolean empty_line = true; //variabile utilizzata per ignorare le eventuali righe vuote nel file
		long time_second= 0; //variabile utilizzata per scandire il passaggio dei secondi
		
		
		table_of_flow_analysis= new Hashtable<InfoKeyFlow, InfoFlow>();
		in = new Scanner(file_of_flows);	
		
		//Salto la prima riga del file, perchè non contiene dati
		//da analizzare ma solo la struttura dei dati stessi
		in.nextLine();
		
		
		
		while (in.hasNextLine()){
			empty_line = true;
			n_field = 0;
			
			String line = in.nextLine();
			//Prendo tutte le sottostringhe della riga del file, separate dal carattere "|"
			StringTokenizer st = new StringTokenizer(line, "|", false); 
			//Genero un array che mi conterrà in ordine i seguenti campi:
			//IPV4_DST_ADDR, IN_PKTS, IN_BYTES, L4_DST_PORT, PROTOCOL
			String[] info_line = new String[5];
			
			
			//Scorro tutte le sottostringhe, le analizzo e
			//recupero quelle rilevanti per l'analisi di un attacco
			while (st.hasMoreTokens()){
				empty_line = false;
				
				String field = st.nextToken().toString();
				try{
					takeFields(info_line, n_field, field);
				}catch(IllegalArgumentException e){
					System.out.println(e.toString());
					return;
				}
				
				//LAST_SWITCHED posizione 8
				if (n_field == 8){
					if ( time_second != 0 && Integer.parseInt(field) > time_second){
						//Significa che è passato almeno un secondo e devo fare un report
						time_second = Integer.parseInt(field);
						try{
							generaReport(table_of_flow_analysis);
						}catch(IllegalArgumentException e){
							System.out.println(e.toString());
							return;
						}	
					}
					else if (time_second == 0){
						//Caso base per l'inizio del conteggio del tempo
						time_second = Integer.parseInt(field);
					}
				}	
				n_field++;				
			}
			 
			
			
			//Se ho incontrato nel file una riga contenente informazioni, allora
			//inserisco nella "table_of_flow_analysis" i valori presi dalla riga.
			//Altrimenti proseguo nella lettura delle altre riga.
			if (!empty_line) {
				try{
					insertInTable(table_of_flow_analysis, info_line, time_second);
				}catch(IllegalArgumentException e){
					System.out.println(e.toString());
					return;
				}catch(NullPointerException e){
					System.out.println(e.toString());
					return;
				}	
			}

			
			
		}	

		//Dopo aver concluso la lettura di tutto il file, 
		//genero il report relativo all'ultimo secondo.
		try{
			generaReport(table_of_flow_analysis);
		}catch(IllegalArgumentException e){
			System.out.println(e.toString());
			return;
		}
		
		//Se analizzando tutto il file non ho trovato attacchi allora
		//scrivo sul file di report e sulla shell
		if (an_attack == 0){
			report_attacks.append("\nNON CI SONO STATI ATTACCHI\n");
			System.out.println("NON CI SONO STATI ATTACCHI\n");
		}
		
	}

	
	
	
	//EFFECTS: metodo che inserisce in una determinata posizione dell' array "info_line", 
	//il parametro "field" secondo le seguenti considerazioni:
	//Il parametro "field" è una sottostringa di una riga di un file.
	//Considerato che si presuppone il file ben strutturato,
	//le sottostringhe da inserire nell' array "info_line"
	//si trovano in precise posizione di ogni riga del file.
	//MODIFIES: modifica il parametro "info_line"
	private static void takeFields(String[] info_line, int n_field, String field){
		
		if(info_line == null || n_field < 0 || field == null){
			throw new IllegalArgumentException("takeFields: viene passato almeno un parametro < 0 o uguale a null");
		}
		
		//IPV4_DST_ADDR posizione 1
		if (n_field == 1){
			info_line[0] = field;
		}
		//IN_PKTS posizione 5
		else if (n_field == 5){
			info_line[1] = field;
		}
		//IN_BYTES posizione 6
		else if(n_field == 6){
			info_line[2] = field;
		}
		//L4_DST_PORT posizione 10
		else if (n_field == 10 ){
			info_line[3] = field;
		}
		//PROTOCOL posizione 12
		else if (n_field == 12 ){
			info_line[4] =  field;
		}
		
	}
	
	
	

	//EFFECTS: metodo che inserisce una nuova coppia (K,V) nella tabella
	//"table_of_flow_analysis", o modifica solo il campo valore V di una chiave K.
	//In entrambi i casi la chiave K e il parametro V vengono calcolati
	//grazie ai parametri di "info_line" e al parametro "time_second".
	//MODIFIES: modifica il parametro "table_of_flow_analysis"
	private static void insertInTable(Hashtable<InfoKeyFlow, InfoFlow > table_of_flow_analysis,
									  String[] info_line, long time_second){
		
		if (table_of_flow_analysis == null || info_line == null || time_second < 0){
			throw new IllegalArgumentException("insertInTable: viene passato almeno un parametro < 0 o uguale a null");
		}
		
		//Creo una chiave per la tabella hash "table_of_flow_analysis"
		InfoKeyFlow key_table = new InfoKeyFlow(info_line[0], Integer.parseInt(info_line[3]),Integer.parseInt(info_line[4]));
		InfoFlow f_temp = null;

		
		//Controllo se è presente la mia chiave "key_table" nella tabella hash.
		//Se è presente: accedo al valore corrispondente "f_temp" 
		//e aggiungo i nuovi dati
		//Se non è presente: creo un oggetto di tipo InfoFlow e 
		//lo assegno come valore corrispondente alla mia chiave
		try {	
			if ( (f_temp=table_of_flow_analysis.get(key_table)) != null){				
				f_temp.addOneFlow(Integer.parseInt(info_line[1]) , Integer.parseInt(info_line[2]) );
			}
			else {
				InfoFlow flow = new InfoFlow( 1, Integer.parseInt(info_line[1]) ,  Integer.parseInt(info_line[2]), time_second);
				table_of_flow_analysis.put(key_table, flow);
			}
		//Risollevo l'eccezione, cosi facendo blocca l'analisi di tutto il file, ma prosegue con
		//l'analisi degli altri file
		}catch (NullPointerException e){
			throw new NullPointerException("insertInTable: errore nella gestione della Tabella Hash");
		}
	}
	
	
	
	
	//EFFECTS: metodo che analizza il parametro "table" alla ricerca di uno o più attacchi,
	//e stampa sia su un file di output sia sulla shell, i dati relativi a tali attacchi. 
	//MODIFIES: il parametro table viene svuotato 
	private static void  generaReport(Hashtable<InfoKeyFlow, InfoFlow > table) {
		
		if(table == null){
			throw new IllegalArgumentException("generaReport: parametro table uguale a null");
		}
		
		 //Salvo tutte le chiavi della tabella table in una variabile di tipo Enumeration
		 Enumeration<InfoKeyFlow> keys = table.keys();
		 //Scorro tutte le chiavi 
	     while(keys.hasMoreElements()){
             InfoKeyFlow key=(InfoKeyFlow) keys.nextElement();
             InfoFlow flow= table.get(key);
             //Se rilevo un attacco stampa sia sulla shell che sul file di output 
             if (flow.isAttached()){
            	 //Segno che c'è stato almeno un attacco nel file
            	 an_attack = 1;
            	 //Stampo il risultato sulla shell
            	 System.out.println("ATTENZIONE: ATTACCO RILEVATO!!!");
            	 System.out.println("IP DESTINATARIO ATTACCATO: " + key.getIPv4Dest()
            	 				   +"\nNUMERO PORTA: " + key.getDstPort()
            	 				   +"\nPROTOCOLLO: " + key.getProtocol()
            			           +"\nNUMERO FLUSSI: " + flow.getNumFlussi()
            			           +"\nNUMERO PACCHETTI: " + flow.getNumPkt()
            			           +"\nNUMERO BYTE TOTALI: " + flow.getNumByte()
            			           +"\nTIME: " + flow.getLastSwitched_inDate() +"\n");
            	 
            	 //Scrivo il risultato sul file di output
            	 report_attacks.append("\nATTENZIONE: ATTACCO RILEVATO!!!");
            	 report_attacks.append("\nIP DESTINATARIO ATTACCATO: " + key.getIPv4Dest()
	            	 				   +"\nNUMERO PORTA: " + key.getDstPort()
	            	 				   +"\nPROTOCOLLO: " + key.getProtocol()
							           +"\nNUMERO FLUSSI: " + flow.getNumFlussi()
							           +"\nNUMERO PACCHETTI: " + flow.getNumPkt()
							           +"\nNUMERO BYTE TOTALI: " + flow.getNumByte()
							           +"\nTIME: " + flow.getLastSwitched_inDate() +"\n");				        	 
             }
	     }
	     
	     //Infine svuoto la tabella hash "table"
	     table.clear();
		
	}
		
	
	
}
