package pkg;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Applicazione {

	// Funzione utilizzata per controllare che il tcpflag non abbia tutti 0.
	public static boolean checkzero(int[] tf){
		int somma = 0;
		for(int i = 0; i<6; i++){
			somma = somma + tf[i];
		}
		if(somma == 0) return true;
		else return false;
	}
	
	/* Funzione che conta quanti sono i flussi aperti per ogni minuto. Costuisce e restituisce un array di interi, 
	 * con tante posizioni quanti i minuti di durata dell'analisi dei flussi, ed ad ogni indice incrementa di 1 quando trova
	 * un flusso aperto in quel minuto.
	 * Parametri: 
	 * - l'arrayList di connessioni, costruito a partire dai file passati come parametro.
	 * - intero che specifica i minuti da considerare come intervallo di analisi.
	 * - intero che indica il valore da considerare come inizio dell'intervallo (preso il SysUpTime del primo flusso valido).
	 */
	public static int[] individuaFlussi(ArrayList<Connessione> conn, int minuti, int iniziotempo){
		int[] flussiaperti = new int[minuti];
		int i = 0;
		int f = 0;
		for(Connessione c : conn){
			if(c.aperta){
				//System.out.println(c.tempoinizio+ " "+c.tempofine+ " "+ iniziotempo);
				i = (c.tempoinizio - iniziotempo) / 60;
				f = (c.tempofine - iniziotempo) / 60;
				//System.out.println(i+" "+f);
				for(;i<=f;i++){
					flussiaperti[i]++;
				}
			}
		}
		
		return flussiaperti;	
	}

	
	/* Funzione per avere una lista di indirizzi e porte riferiti nei vari minuti.
	 * Modifica gli ultimo due parametri con due array bidimensionali di stringhe del caso di ip e di interi 
	 * nel caso delle porte.
	 * I due array hanno lunghezza corrispondente ai minuti di analisi, poi ogni uteriore array interno ha lunghezza
	 * pari al numero delle connessioni aperte per quel minuto.
	 * Parametri: 
	 * - l'arrayList di connessioni, costruito a partire dai file passati come parametro.
	 * - l'array di interi che, restituito dalla individuaFlussi, indica il numero di connessioni al minuto.
	 * - intero che specifica i minuti da considerare come intervallo di analisi.
	 * - intero che indica il valore da considerare come inizio dell'intervallo (preso il SysUpTime del primo flusso valido)
	 * - riferimento ad un array bidimensionale di stringhe;
	 * - riferimento ad un array bidimensionale di interi
	 */
	public static void individuaIPePorta(ArrayList<Connessione> conn, int[] nflussialm,int minuti, int iniziotempo, String[][] arrays, int[][] porte){
		// inizializzo i parametri che saranno utilizzati dal main
		
		for(int i=0;i<minuti;i++){
			int len = nflussialm[i];
			arrays[i] = new String[len];
			porte[i] = new int[len];
		}
		int[] elementiip = new int[minuti]; // indica il numero di elementi che ogni arrays[i] ha, server per l'inserimento
		int[] elementiporte = new int[minuti]; // indica il numero di elementi che ogni porte[i] ha, server per l'inserimento
		int i = 0, f = 0;
		// Per ogni connessione che ho registrato dal file, se aperta, calcolo il minuto di inizio e fine
		// e nei due array bidimensionali inserisco, per ogni minuto in cui essa e' aperta, ip e porta.
		for(Connessione c : conn){
			if(c.aperta){
				i = (c.tempoinizio - iniziotempo) / 60;
				f = (c.tempofine - iniziotempo) / 60;
				
				for(;i<=f;i++){
					// inserisco l'indirizzo ip nella prossima posizione libera e incremento il contatore
					arrays[i][elementiip[i]] = c.A.srcaddr;
					elementiip[i]++;
					// inserisco la porta nella prossima posizione libera e incremento il contatore
					porte[i][elementiporte[i]] = c.A.l4dstport;
					elementiporte[i]++;
				}
			}
		}
		
	}
	
	
	/* Funzione che calcola, a partire da un intero passato come parametro, i valori dei 6 flag del tcp. 
	 */
	public static int[] calcolotcpflags(int tot){
		int[] risultato = new int[6];
		int parziale = tot;
		
		if((parziale - 32)>=0){
			risultato[0] = 1;
			parziale = parziale - 32;
		}
		if((parziale - 16)>=0){
			risultato[1] = 1;
			parziale = parziale - 16;
		}
		if((parziale - 8)>=0){
			risultato[2] = 1;
			parziale = parziale - 8;
		}
		if((parziale - 4)>=0){
			risultato[3] = 1;
			parziale = parziale - 4;
		}
		if((parziale - 2)>=0){
			risultato[4] = 1;
			parziale = parziale - 2;
		}
		if((parziale - 1)>=0){
			risultato[5] = 1;
			parziale = parziale - 1;
		}
		
		return risultato;
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BufferedReader[] filer = null;
		ArrayList<Connessione> connessioni = new ArrayList<Connessione>();
		if(args.length < 1){
			System.out.println("Parametri errati");
			System.exit(1);
		} else {
			int numerofile = args.length;
			//int minuti = Integer.parseInt(args[args.length-1]);
			//System.out.println(numerofile+" ");
			try {
				
				filer = new BufferedReader[numerofile];
				for(int i = 0; i<numerofile; i++)
				filer[i] = new BufferedReader(new FileReader(args[i]));
			
			
				String s = null;
				String template = null;
	
				for(int n=0; n<numerofile; n++){
					BufferedReader reader = filer[n];
					if ((s = reader.readLine()) != null){
							template = s;
							//System.out.println(template);
					}
				
					// Leggendo riga per riga dal file inizio a ricostruire le connessioni.
					while ((s = reader.readLine()) != null){
						String[] dati = s.split("\\|");
						if (dati.length == 18){
							// Creo un oggetto flusso, che descrive il flusso che ho appena letto dal file, e 
							// salva i dati piu' importanti.
							Flusso f = new Flusso(dati[0],dati[1],dati[9],dati[10],dati[5],dati[6],dati[7],dati[8]);
							int tcpf = new Integer(dati[11]).intValue();
							int flagstcp[] = calcolotcpflags(tcpf);
							
							if (checkzero(flagstcp)==false){
								
								if(connessioni.size() == 0){
									// Se l'array connessioni e' vuoto (sono alla lettura della prima riga da file)
									// allora inserisco il nuovo flusso
									Connessione c = new Connessione(f);
									connessioni.add(c);
									if(flagstcp[4]==1){
										c.syninviato = true;
									}
									if(flagstcp[3]==1){
										c.chiusa = true;
									}
									if(flagstcp[5]==1){
										c.fininviato = true;
									}
									c.totpacchetti = f.npkt;
									c.totbytes = f.nbytes;
									
								} else {
									// Se ho gia' altre connessioni nell'array, devo fare dei controlli:
									// La connessione descritta dal flusso esiste gia'?  
									// In caso non aggiungo una nuova connessione ma controllo i tcpflags e annoto 
									// dei cambiamenti, come un nuovo tempo di fine, se e' stato chiuso il flusso.
									Connessione trovatac = null;
									int lato = 0;
									boolean trovata = false;
									int i = 0;
									while(i<connessioni.size() && trovata == false){
										Connessione c = connessioni.get(i);
										if(c.isIn(f)==0){
											trovata = false;
											
										}
										else if(c.isIn(f)==1){
											trovata = true;
											trovatac = c;
											lato = 1;
											
										}
										else if(c.isIn(f)==2){
											trovata = true;
											lato = 2;
											trovatac = c;
											
										}
										i++;
									}
									if(trovata == true){
										if(lato == 1){
											//System.out.println("lato A");
											if(flagstcp[4]==1){
												trovatac.syninviato = true;
												trovatac.tempofine = f.timelastpkt+1;
											}
											if(flagstcp[3]==1){
												trovatac.chiusa = true;
												trovatac.tempofine = f.timelastpkt+1;
												
											}
											if(flagstcp[5]==1){
												trovatac.fininviato = true;
												trovatac.tempofine = f.timelastpkt+1;
											}
											
										} else if(lato ==2){
											//System.out.println("lato B");
											if(flagstcp[4]==1 && flagstcp[1]==1 && trovatac.syninviato == true){
												trovatac.add(f);
												trovatac.aperta = true;
												trovatac.tempoinizio = f.timefirstpkt;
												trovatac.tempofine = f.timelastpkt+1;
												
											}
											if(flagstcp[3]==1){
												trovatac.chiusa = true;
												trovatac.tempofine = f.timelastpkt+1;
											}
											if(flagstcp[5]==1 && flagstcp[1]==1 && trovatac.fininviato){
												trovatac.chiusa = true;
												trovatac.tempofine = f.timelastpkt+1;
											}
										}
										trovatac.totpacchetti = trovatac.totpacchetti + f.npkt;
										trovatac.totbytes = trovatac.totbytes + f.nbytes;
										
									} else {
										//System.out.println("non trovata");
										// Devo aggiungere una nuova connessione
										Connessione c = new Connessione(f);
										connessioni.add(c);
										if(flagstcp[4]==1){
											c.syninviato = true;
										}
										if(flagstcp[3]==1){
											c.chiusa = true;
											c.tempofine = f.timelastpkt+1;
										}
										if(flagstcp[5]==1){
											c.fininviato = true;
										}
										c.totpacchetti = f.npkt;
										c.totbytes = f.nbytes;
									}
								}
							}	
						}
						else {
							System.out.println("ohuj");
						}
						
					}
				}
				
			} catch (FileNotFoundException ex){
				System.out.println("ERRORE: il file non e' stato trovato");
				System.exit(1);
			} catch (IOException ex){
				
			}
			// Stampo tutte le connessioni individuate, aperte e non, chiuse e non.
			for(Connessione c : connessioni){
				System.out.println(c.toString());
			}
	
			// Cerco un valore da dare ad inizio intervallo per la successiva fase di analisi
			// Inolte mi salvo anche il tempo di fine massimo, per verificare che il parametro dei minuti
			// sia valido e non generi successive eccezioni.
			int iniziointervallo = 0;
			int fineintervallo = 0;
			if(connessioni.size()!=0) {
				for(Connessione c : connessioni){
					if(c.aperta==true){	
						if(iniziointervallo == 0) iniziointervallo = c.tempoinizio;
						else {
							if(c.tempoinizio < iniziointervallo) iniziointervallo = c.tempoinizio;
						}
						if(fineintervallo == 0) fineintervallo = c.tempofine;
						else {
							if(c.tempofine > fineintervallo) fineintervallo = c.tempofine;
						}
					}
				}
			} else {
				System.out.println("Non ho individuato connessioni");
				System.exit(1);
			}
			
			// Calcolo i minuti di analisi
			System.out.println("Iniziotempo: " + iniziointervallo);
			System.out.println("Finetempo: " + fineintervallo);
			
			int intervallo = fineintervallo - iniziointervallo;
			int minintervallo = intervallo/60;
			minintervallo++;
			
			System.out.println("Minuti di intervallo: " + minintervallo);
			
			int minuti = minintervallo;

			// Inizio l'analisi, analisi e' un array di interi che mi dice, per ogni minuto quante connessioni aperte ho.
			int[] analisi;
			analisi = individuaFlussi(connessioni,minuti,iniziointervallo);
			
			int max = 0;
			for(int j = 0; j<minuti; j++){
				System.out.println("Al minuto " + (j+1) + " ho " + analisi[j] +" connessioni");
				if(analisi[j]>max) max = analisi[j];
			}
			
			
			// Se in analisi ho almeno un minuto con piu' di 200 connessioni passo all'analisi
			// degli ip e delle porte.
			if(max > 300){
				// indip e' un arraybidimensionale con tante righe quanti i minuti specificati che contiene per colonna
				// tutti gli ip, responsabili di una apertura di una connessione col server, che nel minuto corrispondente
				// tale connessione e' ancora aperta
				String[][] indip = new String[minuti][];
				// Similmente porteserver e' un array bidimensionale di interi con tante righe quanti i minuti che
				// contiene per colonna tutte le porte impegnate in una connessione, dove tale connessione risulta ancora
				// aperta nel minuto corrispodente alla riga
				int[][] porteserver = new int[minuti][];
				// Funzione che mi inizializza indip e porteserver.
				individuaIPePorta(connessioni,analisi,minuti,iniziointervallo,indip,porteserver);
				
				
				
				IndirizziPresenti indpres;
				PortePresenti portepres;
				
				String si = "";
				String s = null;
				int i = 1; // Indica il minuto che sto analizzando
				// Per ogni array di stringhe in indip creo ed inizializzo un oggetto IndirizziPresenti
				// che mi indica quale tra tutti gli ip elencati e' quello che si presenta con maggior frequenza.
				// Se l'ip con maggior frequenza compare almeno 200 volte viene ritenuto responsabile del possibile attacco
				for(String[] ss : indip){
					indpres = new IndirizziPresenti();
					for( String str : ss){
						indpres.aggiungi(str);
					}

					IndirizzoIP ind = indpres.indMaxCouter();
					if(ind!=null && ind.counter > 300){
						s= +i+": "+ ind.ip+",\n\t ";
						//System.out.println("L'ip responsabile delle numerose connessioni al minuto "+i+" e' "+ ind.ip);
						si = si.concat(s);
						i++;
					}
				}
				
				
				i = 1; // Indica il minuto che sto analizzando
				String sp = "";
				s = null;
				// Per ogni array di interi in porteserver inzializzo un oggetto PortePresenti che permette di individuare
				// tra tutti le porte dell'array quella che compare con maggior frequenza, e se essa ha un contatore > 200
				// viene ritenuta la porta principale d'attacco.
				for(int[] elencoporte : porteserver){
					portepres = new PortePresenti();
					for( int po : elencoporte){
						portepres.aggiungi(po);
					}
					
					Porta pmaxc = portepres.indMaxCouter();
					if(pmaxc!=null && pmaxc.counter > 300){
						s = i+": "+ pmaxc.p+",\n\t ";
						sp = sp.concat(s);
						//System.out.println("La porta con piu' connessioni al minuto "+i+": "+ pmaxc.p);
						
						i++;
					}
				}
				System.out.println("Minuto: Ip che ha aperto piu' connessioni \n\t "+si);
				System.out.println("Minuto: Porta con piu' connessioni \n\t "+sp);
				
				
			} else {
				System.out.println("Il file non contiene minuti in cui le connessioni sono state numerose");
			}
			
		}
	}

}
