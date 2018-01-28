
import java.io.*;
import java.net.*;
import java.util.*;
/**
 * Classe che implementa un task che analizza periodicamente la cache, con periodo definito da TIME_OUT.
 * L'analisi consiste appunto nel controllare tutti i record della cache e
 * verificare se vi sono dei flussi terminati, una volta trovati questi vengono
 * eliminati dalla cache e inviati al processo collector. 
 * @author Francesco
 */
public class FlowAnalyzer implements Runnable
{
	/**
	 * La cache dove sono memorizzati i record di flusso
	 */
	private Map<String, NetFlow5Record> cache;
	/**
	 * Tempo di boot del processo
	 */
	private int sysUpTime;
	/**
	 *ID progressivo di flusso
	 */
	private int flowID;
	/**
	 * Socket da cui inviare i flussi al collector
	 */
	private DatagramSocket ds;
	
	 /**
	   * Valore che identifica il numero di secondi
	   * necessari affichè un flusso sia dichiarato troppo lungo
	   */
	private static int FLOW_TOO_LONG_SECONDS;
	 /**
	   * Valore che identifica il numero di secondi
	   * necessari affichè un flusso sia dichiarato inattivo
	  */
	private static int FLOW_INACTIVE_SECONDS;
	/**
	 * Ogni ANALYSIS_FREQUENCY viene analizzata la cache
	 */
	private static long ANALYSIS_FREQUENCY;
	
	/**
	 * Alloca un FlowAnalyzer
	 * @param cache
	 * @param sysUpTime
	 * @param ds
	 */
	public FlowAnalyzer(Map<String, NetFlow5Record> cache,int sysUpTime,DatagramSocket ds)
	{
		this.cache = cache;
		this.sysUpTime = sysUpTime;
		this.flowID = 0;
		this.ds = ds;
	}
	/**
	 * Il Main Task del FlowAnalyzer.
	 */
	@Override
	public void run() 
	{
		/* analyzer set up */ 
		Properties props = new Properties();
		try 
		{
			InputStream in = FlowAnalyzer.class.getClassLoader().getResourceAsStream("Var.properties");
			if(in == null)
			{
				System.out.println("Errore: File di properties non trovato nella cartella");
				System.exit(Probe.EXIT_FAILURE);
			}
			props.load(in);
			
			FLOW_TOO_LONG_SECONDS = Integer.parseInt(props.getProperty("FLOW_TOO_LONG_SECONDS"));
			FLOW_INACTIVE_SECONDS = Integer.parseInt(props.getProperty("FLOW_INACTIVE_SECONDS"));
			ANALYSIS_FREQUENCY = Long.parseLong(props.getProperty("ANALYSIS_FREQUENCY"));
			if(FLOW_TOO_LONG_SECONDS <= 0 || FLOW_INACTIVE_SECONDS <= 0 || ANALYSIS_FREQUENCY <= 0)throw new NumberFormatException();
			props = null;
			in.close();
		}
		catch(NumberFormatException e)
		{
			System.out.println("Errore: Formato Dati Errato nel file di properties");
			System.exit(Probe.EXIT_FAILURE);
		}
		catch(NullPointerException e)
		{
			System.out.println("Errore: Dati mancanti nel file di properties");
			System.exit(Probe.EXIT_FAILURE);
		}
		catch(IOException e)
		{	
			System.out.println("Errore: File di properties non trovato");
			System.exit(Probe.EXIT_FAILURE);
		}
		
		/* analyzer task  */
		for(;;)
		{
			try 
			{
				Thread.sleep(ANALYSIS_FREQUENCY);
			} 
			catch (InterruptedException e1) {}
			
			
			NetFlow5Packet pkt = new NetFlow5Packet();
			short numRec = 0;
			
			synchronized (cache) 
			{
				if(cache.size() != 0)
				{
					/* Controllo se nella cache vi sono flussi terminati */
					Iterator<NetFlow5Record> ite = cache.values().iterator();
					List<String> keys = new LinkedList<String>();
					NetFlow5Record rec;
					while(ite.hasNext())
					{
						rec = ite.next();
						
						/*se la condizione è vera il flusso deve essere inviato al collector ed eliminato dalla cache*/
						if(rec.hasTcpFin() || rec.isInactive(FLOW_INACTIVE_SECONDS) || rec.isTooLong(FLOW_TOO_LONG_SECONDS))
						{
							keys.add(rec.getKey());
							if(pkt.addRecord(rec))
							{
								/*pacchetto non ancora pieno*/
								numRec++;
								
							}
							else 
							{
								/*pacchetto pieno*/
								int now = (int)(System.currentTimeMillis()/1000);
								int processRunTime = now - sysUpTime;
								/* setto l'header al pacchetto*/
								pkt.setHeader(new NetFlow5Header(numRec,processRunTime,now,flowID++)); 
								try 
								{
									send(pkt); /* invio il pacchetto */
								} 
								catch (IOException e) 
								{
									System.out.println("Errore di I/O durante l'invio di flussi");
									System.exit(Probe.EXIT_FAILURE);
								}
								/* pulisco il pacchetto vecchio e inserisco il record che non entrava nel pkt vecchio*/
								pkt = new NetFlow5Packet();
								pkt.addRecord(rec);
								numRec = 1;
							}
							
						}
					}
					
					ite = null;
					
					try 
					{
						if(numRec != 0)
						{
							int now = (int)(System.currentTimeMillis()/1000);
							int processRunTime = now - sysUpTime;
							/* setto l'header al pacchetto*/ 
							pkt.setHeader(new NetFlow5Header(numRec,processRunTime,now,flowID++));
							send(pkt);
						}
						
					} 
					catch (IOException e) 
					{
						System.out.println("Errore di I/O durante l'invio di flussi");
						System.exit(Probe.EXIT_FAILURE);
					}
					
					/* rimuovo le chivi dei record terminati */
					for(String key : keys)
					{
						cache.remove(key);
					}
					
				}
				
			}
		}
		
	}
	/**
	 * Invia sul socket Datagram il  NetFlow5Packet passato per argomento
	 * @param flowPacket il pacchetto da inviare
	 * @throws IOException se vi sono eccezione di I/O
	 */
	private void send(NetFlow5Packet flowPacket) throws IOException
	{
		/* se vi sono flussi terminati si invia il NetFlow5Packet al collector*/
		byte  data [] = new byte [1500];
		DatagramPacket dp = new DatagramPacket(data, data.length, InetAddress.getByName(Probe.ip),Probe.port);
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		DataOutputStream bufWrapper = new DataOutputStream (buf);
		flowPacket.write(bufWrapper);
		data = buf.toByteArray();
		dp.setData(data,0,data.length); // lo inserisco nel DatagramPacket
		dp.setLength(data.length);      // definisco la lunghezza del buffer
		ds.send(dp);                    // invio il DatagramPacket sul socket
		buf.reset();					// svuoto il buffer in spazio utente
	}


}
