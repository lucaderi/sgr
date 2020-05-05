package reti;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
import java.util.GregorianCalendar;
import java.util.Random;
import org.rrd4j.ConsolFun;
import org.rrd4j.DsType;
import org.rrd4j.core.RrdDb;
import org.rrd4j.core.RrdDef;
import org.rrd4j.core.RrdSafeFileBackend;
import org.rrd4j.core.Sample;
import org.rrd4j.core.Util;
import org.rrd4j.graph.RrdGraph;
import org.rrd4j.graph.RrdGraphDef;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

public class Executor
{
	public static void main(String[] args)
    {
		//Parser di argomenti
		ArgumentParser options = new ArgumentParser(args);
        //Directory di partenza
        File dir = null;
        //File Contenente i protocolli
        String fileprotocols = "./Protocols";
        // Path per il DataBase
    	String rrdPath = "/tmp/Database.rrd";
    	// Path per il log 
		String logPath = "/tmp/logfile.log";
    	// Path dei file
		String pathfile = "/tmp/";
		// Path dell'immagine
	    String imgPath = "/tmp/index_file_graphic/";
		// Path del file HTML in otput
	    String htmlPath = "/tmp/VisualGraph.html";
		//logFile
		PrintWriter log = null;
		//DataBase
		RrdDb rrdDb = null;
		//Tempo di partenza per il Database
		long start = Util.getTimestamp(2010, 7,9,0,9);
		//Tempo di fine del grafico
		long end = start +1;
		//Tempo di partenza del grafico
		long start2 = 0L;
		//Tempo finale del grafico
		long end2 = 0L;
		//Usata nel for che indica il numero di anni
    	int i=0;
    	//File contenente i protocolli
    	BufferedReader protocolli = null;
    	//Lista di protocolli
    	ArrayList<String> Arrayprotocolli = new ArrayList<String>();
		//variabile che indica se è stato passato il path del database
    	boolean db;
    	// first, define the RRD
		RrdDef rrdDef = null;
		// anno corrente
		int annocorrente = ((GregorianCalendar.getInstance()).get(Calendar.YEAR));

		//Filtro che ritorna true se è stato passata una directory come parametro 
        FileFilter directoryFilterYear = new FileFilter() {
            public boolean accept(File file) {
                return file.isDirectory();
            }
        };

        //Filtro che ritorna true se è stato passata una directory come parametro che è un giorno
        FileFilter directoryFilterDay = new FileFilter() {
            public boolean accept(File file) {
            	boolean len = file.getName().length() > 1 && file.getName().length() < 3  ;
            	int name = 0;
            	if(len){
            		try{
            			name = (Integer.parseInt(file.getName().substring(0, 2)));
            		}catch(NumberFormatException e){
            			return false;
            		}
            	}
                return file.isDirectory() && name > 0 && name < 32 && len;
            }
        };
        //Filtro che ritorna true se è stato passata una directory come parametro che indica un mese
        FileFilter directoryFilterMonth = new FileFilter() {
            public boolean accept(File file) {
            	boolean len = file.getName().length() > 1 && file.getName().length() < 3  ;
            	int name = 0;
            	if(len){
            		try{
            			name = (Integer.parseInt(file.getName().substring(0, 2)));
            		}catch(NumberFormatException e){
            			return false;
            		}
            	}
                return file.isDirectory() && name > 0 && name < 13 && len;
            }
        };
        //Filtro che ritorna true se è stato passata una directory come parametro che è una ora del giorno
        FileFilter directoryFilterHour = new FileFilter() {
            public boolean accept(File file) {
            	boolean len = file.getName().length() > 1 && file.getName().length() < 3  ;
            	int name = 0;
            	if(len){
            		try{
            			name = (Integer.parseInt(file.getName().substring(0, 2)));
            		}catch(NumberFormatException e){
            			return false;
            		}
            	}
                return file.isDirectory() && name > -1 && name < 61 && len;
            }
        };
      //Filtro che ritorna true se è stato passato come parametro un file con estensione .flow e ha lunghezza pari a 10
        FileFilter  flowsFilter = new FileFilter() {
            public boolean accept(File file) {
            	int mid= file.getName().lastIndexOf(".");
                return file.isFile() && file.getName().substring(mid+1,(int) file.getName().length()).equals("flows") && (file.getName().length() == 8);  
            }
        };

        if(options.hasOption("help") == true){
        	System.out.println(	"Benvenuto in Graphics Protocol v.0.1 \n" +
        						"Copyright 2012-13 by Francesco Licari <licarifrancesco@gmail.com>\n" +
        						"Uso: \n" +
        							 "\tgprotocol      \t[ --help | -help ] \n" +
        							             "\t\t\t[ --db=<path database>] \n" +
        							             "\t\t\t[ --log=<path log file>] \n" +        							             
        							             "\t\t\t[ --file=<file da analizzare>] \n" + 
        							             "\t\t\t[ --protocols=<file contenente i nomi dei protocolli>] \n" +
        							             "\t\t\t[ --html=<directory o nome del file di output dell'html>]\n" +
        							             "\t\t\t[ --start=<minuto/ora/giorno/mese/anno che indica da dove far partire il grafico>]\n" +
        							             "\t\t\t[ --end=<minuto/ora/giorno/mese/anno che indica dove far terminare il grafico>]\n\n\n" +

        							 "[ --help | -help ]                    \t | Comando che visualizza la guida.\n" +
						             "[ --db=<path database>]               \t | L'opzione \"db\" ha una duplice funzione: \n" +
						             							   "\t\t\t\t\t | se viene passato come path un database esistente, \n" +
						             							   "\t\t\t\t\t | allora esso viene aperto e i file vengono aggiunti \n" +
									             				   "\t\t\t\t\t | a tale database, altrimenti, viene creato un nuovo database \n" +
									             				   "\t\t\t\t\t | con il nome scelto. \n" +
									             				   "\t\t\t\t\t | Se invece come path viene passata una directory, \n" +
									             				   "\t\t\t\t\t | il programma cerca un database con il nome \"Database.rrd\", \n" +
									             				   "\t\t\t\t\t | se esiste, tale file viene aperto, altrimenti, \n" +
									             				   "\t\t\t\t\t | il programma crea un database con il nome \"Database.rrd\" \n" +
									             				   "\t\t\t\t\t | nella directory specificata.\n" +
						             "[ --log=<path log file>]              \t | L'opzione \"log\" ha una duplice funzione: \n" +
						             							   "\t\t\t\t\t | se viene passato come path un file di log esistente, \n" +
						             							   "\t\t\t\t\t | allora esso viene aperto e i file vengono aggiunti \n" +
									             				   "\t\t\t\t\t | a tale file, altrimenti, viene creato un nuovo file di log \n" +
									             				   "\t\t\t\t\t | con il nome scelto. \n" +
									             				   "\t\t\t\t\t | Se invece come path viene passata una directory, \n" +
									             				   "\t\t\t\t\t | il programma cerca un file di log con il nome \"logfile.log\", \n" +
									             				   "\t\t\t\t\t | se esiste, tale file viene aperto, altrimenti, \n" +
									             				   "\t\t\t\t\t | il programma crea un file di log con il nome \"logfile.log\" \n" +
									             				   "\t\t\t\t\t | nella directory specificata.\n" +
						             "[ --file=<file da analizzare>]        \t | L'opzione \"file\" riceve come input \n" +
									             				   "\t\t\t\t\t | il path di una directory, \n" +
									             				   "\t\t\t\t\t | il programma cerca ricorsivamente all'interno \n" +
									             				   "\t\t\t\t\t | delle directory i file con estensione \" xx.flows \" , \n" +
									             				   "\t\t\t\t\t | dove per xx si intende dei numeri compresi fra 0 e 59. \n" +
									             				   "\t\t\t\t\t | L'applicazione effettua un'analisi dei file, \n" + 
									             				   "\t\t\t\t\t | riportando le inesattezze in caso di errori. \n" + 
									             				   "\t\t\t\t\t | Alla fine, realizza il grafico e l'applicazine termina. \n" + 
						             "[ --protocols=<path file protocolli>] \t | L'opzione \"protocols\" serve per dare al programma\n" +
									             			       "\t\t\t\t\t | i nomi dei protocolli \n" +
									             				   "\t\t\t\t\t | che sono rilevanti per il suo lavoro, \n" +
									             				   "\t\t\t\t\t | tale opzione di default contiene tutti i protocolli, \n" +
									             			 	   "\t\t\t\t\t | riconoscibili dal programma nprobe, se così non fosse \n" +
									             			 	   "\t\t\t\t\t | si consiglia di scaricare gli aggiornamenti.\n" + 
						             "[ --html=<nome del file dell'html>]   \t | L'opzione \"html\" serve per dare al programma\n"  +
		             			      							   "\t\t\t\t\t | il path di dove mettere il file di output in formato html \n" +
									             			       "\t\t\t\t\t | che fa visualizzare il grafico. \n" +
									             			       "\t\t\t\t\t | se viene passato il nome del file html allora il file avrà \n" +
									             			       "\t\t\t\t\t | quel nome, altrimenti se viene passata una directory, \n" +
									             			       "\t\t\t\t\t | il sistema assegnerà automaticamente il nome: VisualGraph.html . \n" +
						             "[ --start=<minuto/ora/giorno/mese/anno>] | Opzione che indica da quale data far partire il grafico \n" +
		             			       							   "\t\t\t\t\t | esempio:10/20/02/6/2012 \n" +
		             			       							   "\t\t\t\t\t | default: data di creazione database. \n" +
						             "[ --end=<minuto/ora/giorno/mese/anno>]   | Opzione che indica in quale data far terminare il grafico \n" +
		             			       							   "\t\t\t\t\t | esempio:19/20/02/7/2012 \n" +
						             							   "\t\t\t\t\t | default: data ultimo aggiornamento database.\n"
	);
        	System.exit(-1);
        }
        
        if(options.hasOption("start") == true){
        	String startGraph = options.getOption("start");
        	int minuto = 0;
        	int ora = 0;
        	int giorno = 0;
        	int mese = 0;
        	int anno = 0;
        	if(countCharOccurrences(startGraph, '/')==4){
        		int conta = 0;
        		String current = "";
        		for(int jj = 0; jj < startGraph.length() ; jj++){
        			if(startGraph.charAt(jj) == '/' || jj == startGraph.length() - 1){
        				if(jj == startGraph.length() - 1){
        					current += startGraph.charAt(jj);
        				}
        				Integer val = -1;
        				try{
        					val = Integer.parseInt(current);
        				}catch(NumberFormatException e){
    						System.out.println("Formato data del parametro \"start\" errato: la data non può contenere caratteri alfabetici");
    						System.exit(-1);
        				}
        				if(conta==0){
           					if( val > 59){
        						System.out.println("Formato data del parametro \"start\" errato: il minuto non può essere maggiore di 59");
        						System.exit(-1);
           					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"start\" errato: il minuto non può essere negativo");
        						System.exit(-1);
        					}
        					minuto = val.intValue();
        				}
        				if(conta==1){
        					if( val > 24){
        						System.out.println("Formato data del parametro \"start\" errato: l'ora non può essere maggiore di 24");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"start\" errato: l'ora non può essere negativa");
        						System.exit(-1);
        					}
        					ora = val.intValue();
        				}
        				if(conta==2){
        					if( val > 31){
        						System.out.println("Formato data del parametro \"start\" errato: il giorno non può essere maggiore di 31");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"start\" errato: il giorno non può essere negativo");
        						System.exit(-1);
        					}
        					giorno = val.intValue();
        				}        				
           				if(conta==3){
        					if( val > 12){
        						System.out.println("Formato data del parametro \"start\" errato: il mese non può essere maggiore di 12");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"start\" errato: il mese non può essere negativo");
        						System.exit(-1);
        					}
        					mese = val.intValue();
        				}
           				if(conta==4){
           					if( val > annocorrente){
        						System.out.println("Formato data del parametro \"start\" errato: l'anno non può essere maggiore dell'anno corrente");
        						System.exit(-1);
           					}
        					if(val < 1000){
        						System.out.println("Formato data del parametro \"start\" errato: l'anno non può essere minore di 1000");
        						System.exit(-1);
        					}
        					anno = val.intValue();
           				}
           				conta++;
           				current = "" ;
        			}else{
        				current += startGraph.charAt(jj);
        			}
        		}
        	}else{
        		System.out.println("Formato data del parametro \"start\" errato: la data deve essere del tipo: Minute/hourOfDay/date/month/year   Es. 59/24/31/12/2010");
        		System.exit(-1);
        	}
        	start2 = Util.getTimestamp(anno, mese, giorno, ora , minuto);
        }

        if(options.hasOption("end") == true){
        	String endGraph = options.getOption("end");
        	int minuto = 0;
        	int ora = 0;
        	int giorno = 0;
        	int mese = 0;
        	int anno = 0;
        	if(countCharOccurrences(endGraph, '/')==4){
        		int conta = 0;
        		String current = "";
        		for(int jj = 0; jj < endGraph.length() ; jj++){
        			if(endGraph.charAt(jj) == '/' || jj == endGraph.length() - 1){
        				if(jj == endGraph.length() - 1){
        					current += endGraph.charAt(jj);
        				}
        				Integer val = 0;
        				try{
        					val = Integer.parseInt(current);
	    				}catch(NumberFormatException e){
							System.out.println("Formato data del parametro \"end\" errato: la data non può contenere caratteri alfabetici");
							System.exit(-1);
	    				}
        				if(conta==0){
           					if( val > 59){
        						System.out.println("Formato data del parametro \"end\" errato: il minuto non può essere maggiore di 59");
        						System.exit(-1);
           					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"end\" errato: il minuto non può essere negativo");
        						System.exit(-1);
        					}
        					minuto = val.intValue();
        				}
        				if(conta==1){
        					if( val > 24){
        						System.out.println("Formato data del parametro \"end\" errato: l'ora non può essere maggiore di 24");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"end\" errato: l'ora non può essere negativa");
        						System.exit(-1);
        					}
        					ora = val.intValue();
        				}
        				if(conta==2){
        					if( val > 31){
        						System.out.println("Formato data del parametro \"end\" errato: il giorno non può essere maggiore di 31");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"end\" errato: il giorno non può essere negativo");
        						System.exit(-1);
        					}
        					giorno = val.intValue();
        				}        				
           				if(conta==3){
        					if( val > 12){
        						System.out.println("Formato data del parametro \"end\" errato: il mese non può essere maggiore di 12");
        						System.exit(-1);
        					}
        					if(val < 0){
        						System.out.println("Formato data del parametro \"end\" errato: il mese non può essere negativo");
        						System.exit(-1);
        					}
        					mese = val.intValue();
        				}
           				if(conta==4){
           					if( val > annocorrente){
        						System.out.println("Formato data del parametro \"end\" errato: l'anno non può essere maggiore dell'anno corrente");
        						System.exit(-1);
           					}
        					if(val < 1000){
        						System.out.println("Formato data del parametro \"end\" errato: l'anno non può essere minore di 1000");
        						System.exit(-1);
        					}
        					anno = val.intValue();
           				}
           				conta++;
           				current = "" ;
        			}else{
        				current += endGraph.charAt(jj);
        			}
        		}
        	}else{
        		System.out.println("Formato data del parametro \"end\" errato: \n la data deve essere del tipo: Minute/hourOfDay/date/month/year   Es. 59/24/31/12/2012");
        		System.exit(-1);
        	}
        	end2 = Util.getTimestamp(anno, mese, giorno, ora , minuto);
        	if(start2 != 0L && start2 > end2){
        		System.out.println("Attenzione la data del parametro \"end\" deve essere maggiore del parametro start. ");
        		System.exit(-1);
        	}
        }
        
        if(db = options.hasOption("db") == true){
			rrdPath = options.getOption("db");
			try{
				rrdDb = new RrdDb(rrdPath, false);
				System.out.println("== Opening RRD file " + rrdPath );
				rrdDef = rrdDb.getRrdDef();
			} catch (IOException e) {
					if(rrdPath.charAt(rrdPath.length()-1)=='/'){
						rrdPath += "Database.rrd";
						try {
							rrdDb = new RrdDb(rrdPath, false);
							System.out.println("== Opening RRD file " + rrdPath );
							rrdDef = rrdDb.getRrdDef();
						} catch (IOException e1){
							System.out.println("==" + e1.getMessage() );
							System.exit(-1);
						}

						
					}else{
						if(new File(rrdPath).isDirectory()){
							rrdPath += "/Database.rrd";
							try {
								rrdDb = new RrdDb(rrdPath, false);
								System.out.println("== Opening RRD file " + rrdPath );
								rrdDef = rrdDb.getRrdDef();
							} catch (IOException e1){
								System.out.println("==" + e1.getMessage() );
								System.exit(-1);
							}
						}
					}
					String directory =rrdPath.substring(0, rrdPath.lastIndexOf('/'));
					boolean exists = (new File(directory).isDirectory());
					if (!exists) {
						if(rrdPath.lastIndexOf('/') == -1){
							System.out.println("Attenzione la directory: \"" + rrdPath + "\" non esiste"  );									
						}else{
							System.out.println("Attenzione la directory; \"" + rrdPath.substring(0, rrdPath.lastIndexOf('/')) + "\" non esiste"  );		
						}
						System.exit(-1);
					}
				db = false;
			}
		}
		
		if(options.hasOption("html") == true){
			htmlPath = options.getOption("html");
			if(htmlPath.charAt(htmlPath.length()-1)=='/'){
				imgPath = htmlPath + "index_file_graphic/";
				htmlPath += "VisualGraph.html";
			}else{
				if(new File(htmlPath).isDirectory()){
					imgPath = htmlPath + "/index_file_graphic/";
					htmlPath += "/VisualGraph.html";
				}
				imgPath = htmlPath.substring(0, htmlPath.lastIndexOf('/')) + "/index_file_graphic/";
			}
		}
		String directory = htmlPath.substring(0, htmlPath.lastIndexOf('/'));
		boolean exists = (new File(directory).isDirectory());
		if (!exists) {
			if(htmlPath.lastIndexOf('/') == -1){
				System.out.println("Attenzione la directory per il file html: \"" + htmlPath + "\" non esiste"  );							
			}else{
				System.out.println("Attenzione la directory per il file html: \"" + htmlPath.substring(0, htmlPath.lastIndexOf('/')) + "\" non esiste"  );		
			}
			System.exit(-1);
		}else{
			File dirNew = new File(imgPath);
			boolean exists2 = (dirNew.exists());
			if(!exists2){
				dirNew.mkdir();
				System.out.println(dirNew.getAbsolutePath());
			}
		}
		
		
		if(options.hasOption("log") == true){
			logPath = options.getOption("log");
			if(logPath.charAt(logPath.length()-1)=='/'){
				logPath += "logfile.log";
			}else{
				if(new File(logPath).isDirectory()){
					logPath += "/logfile.log";				
					}
			}
		}

		if(options.hasOption("file") == true){
			pathfile = options.getOption("file");
		}
		
		dir = new File(pathfile);
		if(dir == null || dir.isDirectory() == false){
			System.out.println("Directory \"" + pathfile + "\" inesistente");
			System.exit(-1);
		}

		if(options.hasOption("protocols") == true){
			fileprotocols = options.getOption("protocols");
			if(fileprotocols.charAt(fileprotocols.length()-1)=='/'){
				fileprotocols += "Protocols";
			}else{
				if(new File(fileprotocols).isDirectory()){
					fileprotocols += "/Protocols";				
					}
			}
		}
		
		try {
			System.out.println("== Creating Log file " + logPath );
			log = new PrintWriter(new BufferedOutputStream(new FileOutputStream(logPath , false)));
		} catch (IOException e) {
			System.out.println("Errore nella creazione del file di log");
			System.exit(-1);
		}
		
		String pr = "";
		try {
			pr = new File(fileprotocols).getCanonicalPath();
			protocolli = new BufferedReader(new FileReader(fileprotocols));
    		while( protocolli.ready()){
    			Arrayprotocolli.add(protocolli.readLine());
    		}

		}catch (FileNotFoundException e1) {
			log.println(e1.getMessage());
			System.out.println("Attenzione errore nella lettura del file contenente i protocolli, il file \" " + pr + "\" non esiste");
			System.exit(-1);
		}catch (IOException e) {
			log.println(e.getMessage());
			System.out.println("Attenzione errore nella lettura del file contenente i protocolli: " + e.getMessage());
			System.exit(-1);
		}
     
		try {
			protocolli.close();
		} catch (IOException e1) {
			System.out.println("Attenzione errore nella chiusura del file contenente i protocolli");
		}
        File[] files = dir.listFiles(directoryFilterYear);
        ArrayList<File> anni =  new ArrayList<File>();

        
        if(files == null ){
			System.out.println("Directory contenente gli anni in: \"" + pathfile + "\" inesistente");
			System.exit(-1);
		}
		
        for (i=0; i < files.length ; i++){
        	if (files[i].getName().toString().compareTo(((Integer) annocorrente).toString()) == 0){
        		anni.add(files[i]);
        		annocorrente = annocorrente - 1;
        	}
        }
        if (anni.size() != 0){
		    for(i=0; i< anni.size();i++){
		        File[] mesi = null;
		    	mesi = anni.get(i).listFiles(directoryFilterMonth);
		    	Arrays.sort(mesi, new FileDateComparator());
		        for(int j=0; j< mesi.length;j++){
			    	File[] giorni = null;
			    	giorni =  mesi[j].listFiles(directoryFilterDay);
			    	Arrays.sort(giorni, new FileDateComparator());
		            for(int k=0; k< giorni.length;k++){
		    	    	File[] ore = null;
		    	    	ore = giorni[k].listFiles(directoryFilterHour);
		    	    	Arrays.sort(ore, new FileDateComparator());
		                for(int y=0; y< ore.length;y++){
		        	    	File[] minuti = null;
		        	    	minuti = ore[y].listFiles(flowsFilter);
		        	    	Arrays.sort(minuti, new FileDateComparator());
		        	    	BufferedReader in = null;
							for(int h=0; h <  minuti.length;h++){
						        ListaConcatenata lista = new ListaConcatenata();
						        lista.addNameProtocol(fileprotocols);
						        lista.setData((int)Integer.parseInt(anni.get(i).getName().substring(0, 4)), (int)Integer.parseInt(mesi[j].getName().substring(0, 2)), (int)Integer.parseInt(giorni[k].getName().substring(0, 2)), (int)Integer.parseInt(ore[y].getName().substring(0, 2)), (int)Integer.parseInt(minuti[h].getName().substring(0, 2)));
								lista.setFilename(minuti[h].getAbsolutePath());
								log.println("Analysis file: " +  minuti[h]);
								System.out.println("Analysis file: " +  minuti[h]);
								if(db == false && h == 0 && y == 0 && k == 0 && j == 0 && i == 0){
									start = lista.getData();
									rrdDef = definisciRrdDef(rrdDef, rrdPath, start , log, Arrayprotocolli);
									rrdDb = definisciNuovoDatabase(rrdDb, rrdDef, log);
									db=true;
								}
								try {
									in = new BufferedReader(new FileReader(minuti[h].toString()));
									int riga = 0;
									int conta=0; // indica il numero di '|' prima del protocollo
									int indexprotocol = 0;
									// type è true se è presente L7_PROTO altrimenti se è presente L7_PROTO_NAME è false
									boolean type = true; 
									while (in.ready() && conta != -1){ 
										  String text = in.readLine();
										  	if (riga == 0) {
											  	conta=contaNumeroPipeL7_PROTO(conta,indexprotocol, text);
											  	if(conta == -1){
													conta=contaNumeroPipeL7_PROTO_NAME(conta,indexprotocol, text);
													if(conta != -1){
														type = false;
													}else{
												  		log.print("Attenzione il File: " + minuti[h].getAbsolutePath() + " non contiene informazione sul numero di protocollo a livello 7 utilizzato");
														System.out.println("Attenzione il File: " + minuti[h].getAbsolutePath() + " non contiene informazione sul numero di protocollo a livello 7 utilizzato");
													}
											  	}
										  	}else{
										  		if( conta!= - 1){
											  		try{
											  			trovaProtocolloEInserisciInLista(lista,conta, text, type);
											  		}catch(NumberFormatException e){
														log.println(e.getMessage());
														log.print("Attenzione il File: " + minuti[h].getAbsolutePath() + " forse è corrotto, problema con la riga " + riga);
														System.out.println("Attenzione il File: " + minuti[h].getAbsolutePath() + " forse è corrotto, problema con la riga " + riga);
											  		}
										  		}
										  	}
										  	riga++;
										}
									
									
										/*for(int i1=0; i1 < lista.size() ; i1++){
											Nodo node =  lista.getNode(i1);
											System.out.println("Nome Protocollo = " + node.name_protocol + " Protocollo = " + node.prot + " occorrenze = " + node.occ + " percentuale = " + node.percentuale );
										}*/
										if(lista.occorrenzetotali() != 0){
											lista.calcolapercentuali();
											
											if(start > lista.getData()){
									          	start = lista.getData();
									        }
								            if(end < lista.getData()){
								            	end = lista.getData();
								            }	
								            //inserisce i dati nel database
								            inserisciNelDb(log, rrdDef, rrdDb, lista);
										}
								} catch (IOException e) {
									log.println(e.getMessage());
									System.out.println("Errore nella lettura del file \"" + minuti[h] + "\" : \n " + e.getMessage() );
								}
								
								try {
									in.close();
								} catch (IOException e) {
									System.out.println("Errore nella chiusura del file \"" + minuti[h] + "\" : \n " + e.getMessage() );
								}
							   
							}
		                }
		            }
		        }
		    }
		
			creaGrafico(imgPath, htmlPath ,fileprotocols, rrdPath, log, start, end, start2, end2, rrdDb, Arrayprotocolli);
        }else{
			System.out.println("Directory contenente gli anni in: \"" + pathfile + "\" inesistente");
			System.exit(-1);
		}
    }





	
	
	
	

	
	


	private static RrdDef definisciRrdDef(RrdDef rrdDef, String rrdPath, long start, PrintWriter log, ArrayList<String> arrayprotocolli) {
		rrdDef = new RrdDef(rrdPath, start - 1, 300);
		System.out.println("== Creating RRD file " + rrdPath );
		for(int ii = 0; ii < arrayprotocolli.size() ; ii++){
			rrdDef.addDatasource(arrayprotocolli.get(ii), DsType.GAUGE, 600, 0, Double.NaN);
		}
	    rrdDef.addArchive(ConsolFun.AVERAGE, 0.5, 1, 600);
	    rrdDef.addArchive(ConsolFun.AVERAGE, 0.5, 6, 700);
	    rrdDef.addArchive(ConsolFun.AVERAGE, 0.5, 24, 775);
	    rrdDef.addArchive(ConsolFun.AVERAGE, 0.5, 288, 797);
		rrdDef.addArchive(ConsolFun.TOTAL, 0.5, 1, 600);
	    rrdDef.addArchive(ConsolFun.TOTAL, 0.5, 6, 700);
	    rrdDef.addArchive(ConsolFun.TOTAL, 0.5, 24, 775);
	    rrdDef.addArchive(ConsolFun.TOTAL, 0.5, 288, 797);
	    rrdDef.addArchive(ConsolFun.MAX, 0.5, 1, 600);
	    rrdDef.addArchive(ConsolFun.MAX, 0.5, 6, 700);
	    rrdDef.addArchive(ConsolFun.MAX, 0.5, 24, 775);
	    rrdDef.addArchive(ConsolFun.MAX, 0.5, 288, 797);
	    log.println(rrdDef.dump());
	    System.out.println("Estimated file size: " + rrdDef.getEstimatedSize());
	    return rrdDef;
	}


	private static RrdDb definisciNuovoDatabase(RrdDb rrdDb, RrdDef rrdDef, PrintWriter log) {

		try {
			rrdDb = new RrdDb(rrdDef);
			System.out.println("== RRD file created.");

		} catch (IOException e) {
			log.println(e.getMessage());
			System.out.println("Non è stato possibile creare il Database: " + e.getMessage());
			System.exit(-1);
		}
		return rrdDb;
		
	}


	private static int contaNumeroPipeL7_PROTO(int conta, int indexprotocol,String text) {
		if (text.contains("L7_PROTO_NAME")){
			if (text.contains("L7_PROTO")){
				if (text.indexOf("L7_PROTO") == text.indexOf("L7_PROTO_NAME")){
					indexprotocol= text.indexOf("L7_PROTO",1 + text.indexOf("L7_PROTO_NAME"));
				}else{
					indexprotocol= text.indexOf("L7_PROTO");
				}
			}else{
				return -1;
			}		
		}else{
			if (text.contains("L7_PROTO")){
				indexprotocol = text.indexOf("L7_PROTO");	
			}else{
				return -1;
			}
		}
		if (indexprotocol != -1){
			for(int l=0;l<indexprotocol;l++){
				if (text.charAt(l) == '|')
					conta++;
			}
		}else{
			return -1;
		}
		return conta;
	}

	private static int contaNumeroPipeL7_PROTO_NAME(int conta, int indexprotocol,String text) {
		conta = 0;
		if (text.contains("L7_PROTO_NAME")){
					indexprotocol= text.indexOf("L7_PROTO_NAME");
					if (indexprotocol != 0){
						for(int l=0;l<indexprotocol;l++){
							if (text.charAt(l) == '|')
								conta++;
						}
					}
					return conta;
			}else{
				return -1;
			}		
	}
	
	
	private static void trovaProtocolloEInserisciInLista(ListaConcatenata lista, int conta, String text, boolean type) throws NumberFormatException {
		int index2 = 0;
		int index = 0;
			for(int l = 0;l < conta && index < text.length();index++){
				if (text.charAt(index) == '|' ){
					l++;
				}
			}
			for(int l = index; l != -1 && l < text.length() ;l++){
				if (text.charAt(l) == '|') {
					index2 = l-1;
					l = -2;
				}
				if(l == text.length()-1){
					index2 = l;
				}
			}
			
			if( index < text.length() && index2 < text.length()){
				if(type == true){
					lista.add(Integer.parseInt(text.substring(index,index2+1)));
				}else{
					lista.add(text.substring(index,index2+1));
				}	
				
			}	
				
			
	}


	private static void inserisciNelDb(PrintWriter log, RrdDef rrdDef, RrdDb rrdDb, ListaConcatenata lista){
		try {
			if( rrdDb.getLastUpdateTime() < lista.getData() ){
				Sample sample = null;
				try {
					sample = rrdDb.createSample();
				} catch (IOException e1) {
					log.println(e1.getMessage());
					System.out.println("Non è stato possibile caricare il file: " + lista.getFilename());
				}
				
				for(int count = 0 ; count < lista.size(); count++){
					Nodo node = lista.getNode(count);
					sample.setTime((lista.getData()));
					sample.setValue(node.name_protocol, node.percentuale);
				}
				
				log.println(sample.dump());
				
				try {
					sample.update();
					if (rrdDb.getRrdDef().equals(rrdDef) == false) {
						System.out.println("Invalid RRD file created. This is a serious bug, bailing out");
						log.println("Invalid RRD file created. This is a serious bug, bailing out");
						System.exit(-1);
					}
				} catch (IOException e) {
					System.out.println("Non è stato possibile caricare i dati dal file: " + lista.getFilename());
					log.println(e.getMessage());
				} catch (IllegalArgumentException e) {
					System.out.println("Non è stato possibile caricare i dati dal file: " + lista.getFilename());
					log.println(e.getMessage());
					System.exit(-1);
				}
			}else{
				System.out.println("La data del file: " + lista.getFilename() + " è minore di quello dell'ultimo aggiornamento, tale file non è stato preso in considerazione ");
			}
		} catch (IOException e) {
			System.out.println(e.getMessage());
			log.println(e.getMessage());		
			System.exit(-1);
			}
	}
	

	private static void creaGrafico(String imgPath, String htmlPath, String fileprotocols, String rrdPath, PrintWriter log, long start, long end, long start2, long end2,RrdDb rrdDb, ArrayList<String> Arrayprotocolli) {

	        try {
				System.out.println("== Last update time was: " + rrdDb.getLastUpdateTime());
				System.out.println("== Last info was: " + rrdDb.getInfo());
			} catch (IOException e) {
				log.println(e.getMessage());
				System.exit(-1);
			}
		    final int IMG_WIDTH = 900;
		    final int IMG_HEIGHT = 500;

		      // create graph
			System.out.println("Creating graph " + Util.getLapTime());
			System.out.println("== Creating graph from the second file");
	        RrdGraphDef gDef = new RrdGraphDef();
	        gDef.setWidth(IMG_WIDTH);
	        gDef.setHeight(IMG_HEIGHT);
	        gDef.setFilename(imgPath + "myimage2.png");
	        GregorianCalendar dateStart = new GregorianCalendar();
	        GregorianCalendar dateEnd = new GregorianCalendar();
	        if(start2 != 0L){
	        	if(start2 >= 0L)
	        	gDef.setStartTime(start2);
	        	dateStart.setTime(Util.getDate(((start2))));
	        }else{
		        gDef.setStartTime(start);
	        	dateStart.setTime(Util.getDate(((start))));
	        }
	        if(end2 != 0L){
	        	gDef.setEndTime(end2);
		        dateEnd.setTime(Util.getDate(((end2))));
	        }else{
	        	gDef.setEndTime(end);
		        dateEnd.setTime(Util.getDate(((end))));
	        }

	        int yearStart = dateStart.get(Calendar.YEAR);
	        int monthStart = dateStart.get(Calendar.MONTH);
	        int dayStart = dateStart.get(Calendar.DAY_OF_MONTH);
	        int yearEnd = dateEnd.get(Calendar.YEAR);
	        int monthEnd = dateEnd.get(Calendar.MONTH);
	        int dayEnd = dateEnd.get(Calendar.DAY_OF_MONTH);
	        if(yearStart == yearEnd && dayStart== dayEnd && monthEnd == monthStart){
		        gDef.setTitle("Statistiche Utilizzo Internet Del " +  dayStart +"/" + monthStart + "/" + yearStart);
	        }else{
	        	gDef.setTitle("Statistiche Utilizzo Internet Dal " +  dayStart +"/" + monthStart + "/" + yearStart + " Al " + dayEnd +"/" + monthEnd + "/" + yearEnd  );
	        }
	        gDef.setVerticalLabel("Percentuale");
	        
	        //gDef.datasource("median", "sun,shade,+,2,/");
			int color = 1;
			for(int ii = 0; ii < Arrayprotocolli.size() ; ii++){
				String read = Arrayprotocolli.get(ii); 
				gDef.datasource(read, rrdPath, read, ConsolFun.AVERAGE);
				
				try {
					if (rrdDb.getDatasource(read).getAccumValue() >= 3){
						gDef.line(read, getColor(color), read , 2);
						gDef.gprint(read, ConsolFun.MAX, "max = %.3f%s");
						gDef.gprint(read, ConsolFun.AVERAGE, "avg = %.3f%S\\c");
						color++;
					}
				} catch (IOException e) {
					log.println(e.getMessage());
					System.out.println("Errore nella creazione del grafico:" + e.getMessage());
				}
				
			}
			gDef.setTextAntiAliasing(true);
			gDef.setInterlaced(true);
		    gDef.setMinValue(0);
		    gDef.setMaxValue(100);
		    gDef.comment("\\r");
		    gDef.setImageInfo("<img src='%s' width='%d' height = '%d'>");
		    gDef.setPoolUsed(false);
		    gDef.setImageFormat("png");
		    System.out.println("Rendering graph " + Util.getLapTime());
		    // create graph finally
		    RrdGraph graph = null;
			try {
				graph = new RrdGraph(gDef);
				log.println(graph.getRrdGraphInfo().dump());
				System.out.println("== Graph created " + Util.getLapTime());
		        // locks info
		        log.println("== Locks info ==");
		        log.println(RrdSafeFileBackend.getLockInfo());
		        createImageZoom(imgPath);
                
			} catch (IOException e) {
				log.println(e.getMessage());
				System.out.println("Errore nella creazione del grafico: " + e.getMessage());
				System.exit(-1);
			}
			catch (IllegalArgumentException e) {
				log.println(e.getMessage());
				System.out.println(e.getMessage());
				System.out.println("Errore nella creazione del grafico: " + e.getMessage());
				e.printStackTrace();
			}
			       
			try {
				rrdDb.close();
				log.println("== RRD file closed");
				System.out.println("== RRD file closed");
			} catch (IOException e) {
				log.println(e.getMessage());
				System.out.println("Errore nella chiusura del Database: " + e.getMessage());
			}
			
	        log.close();
	        copyfile("mojozoom.css", imgPath + "mojozoom.css", log);
	        copyfile("mojozoom.js", imgPath + "mojozoom.js", log);
	        copyfile("img.html", htmlPath, log);
	
	}


	private static void createImageZoom(String imgPath) throws IOException {
		File a = new File(imgPath + "myimage2.png");
		Image ii = ImageIO.read(a);
		BufferedImage bi = new BufferedImage(1800, 1200,((BufferedImage) ii).getType() == 0 ? 
				BufferedImage.TYPE_INT_ARGB : 
				((BufferedImage) ii).getType()
		    );
		Graphics2D g = (Graphics2D)bi.createGraphics();
		g.setComposite(AlphaComposite.Src);
		g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,RenderingHints.VALUE_INTERPOLATION_BILINEAR);
		g.setRenderingHint(RenderingHints.KEY_RENDERING,RenderingHints.VALUE_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
		g.addRenderingHints(new RenderingHints(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY));
		g.drawImage(ii, 0, 0, 1800,1200, null);
		ImageIO.write(bi, "png", new File(imgPath + "myimage.png"));
	}

	
	private static Color getColor(int i) {
		if(i == 1)
			return new Color(255, 255, 0); 			// Giallo
		if(i == 2)
			return new Color(255 , 0 , 0); 			//Rosso
		if(i == 3)
			return new Color(0, 0, 255 );			//Blu 
		if(i == 4)
			return new Color(0, 255, 0);			//Verde
		if(i == 5)
			return new Color(255, 192, 203);		//Rosa
		if(i == 6)
			return new Color(0, 255, 255);			//Ciano
		if(i == 7){
			return new Color(0, 0, 0);				//Nero
		}else{
			Random randomGenerator = new Random();
			int r = randomGenerator.nextInt(255);
			int g = randomGenerator.nextInt(255);
			int b = randomGenerator.nextInt(255);
			return new Color(r,g,b);
		}
	}    

	 private static void copyfile(String srFile, String dtFile, PrintWriter log ){
		  try{
			  File f1 = new File(srFile);
			  File f2 = new File(dtFile);
			  InputStream in = new FileInputStream(f1);
			  OutputStream out = new FileOutputStream(f2);
		
			  byte[] buf = new byte[1024];
			  int len;
			  while ((len = in.read(buf)) > 0){
				  out.write(buf, 0, len);
			  }
			  in.close();
			  out.close();
			  log.println("File copied " + f2.getAbsolutePath());
			  System.out.println("File copied " + f2.getAbsolutePath());
		  }
		  catch(FileNotFoundException ex){
			  log.println(ex.getMessage() + " in the specified directory");
			  System.out.println(ex.getMessage() + " in the specified directory");
			  System.exit(-1);
		  }
		  catch(IOException e){
			  log.println(e.getMessage());
			  System.out.println(e.getMessage());  
			  System.exit(-1);
		  }
	}
	 
	 public static int countCharOccurrences(String source, char target) {
		 int counter = 0;
		 for (int i = 0; i < source.length(); i++) {
			 if(source.charAt(i) == target){
				 counter++;
			 }
		 }
		 return counter;
	}
}
	  
class FileDateComparator implements Comparator<Object> {
    public int compare(Object arg0, Object arg1) {
      File file1 = (File)arg0;
      File file2 = (File)arg1;
      long delta = Integer.parseInt(file1.getName().substring(0, 2)) - Integer.parseInt(file2.getName().substring(0, 2));
      if (delta < 0) return -1;
      else if (delta > 0) return 1;
      return 0;
    }
  }
