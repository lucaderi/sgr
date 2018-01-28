import java.util.*;
import java.io.IOException;
import java.net.*;
/**
 * Classe che implementa il task main del processo Probe.
 * @author Francesco
 */
public class Probe {
	
	
	public static final int EXIT_SUCCESS = 0;
	public static final int EXIT_FAILURE = -1;
	
	public static String nic = null;
	public static String ip = null;
	public static String bpf = null;
	public static int port = 0;
	
	/**
	 * Il socket su cui vengono inviati i dati al collector
	 */
	private static DatagramSocket ds;
	/**
	 * Processo Probe ativa 
	 * @param args la porta su cui su cui è in ascolto il processo
	 */
	public static void main(String[] args) 
	{
		try
		{
			boolean ok = true;
			if(args.length == 1 && args[0].equals("--help"))
			{
				System.out.println("Sintassi: -i networkInterfaceName -o host:port [-f bfpFilter]");
				System.exit(EXIT_SUCCESS);
			}
			
			if(args.length >= 4 )
			{

				if(args[0].equals("-i"))nic = args[1];
				else ok = false;
				
				if(args[2].equals("-o"))
				{
					String buf[] = args[3].split(":");
					if(buf.length == 2)
					{
						ip = buf[0];
						InetAddress.getByName(ip); /*controllo se ip è un IP valido altrimenti sollevo eccezione */
						port = Integer.parseInt(buf[1]);
					}
				}else ok = false;
				
				if(args.length > 4)
				{
					if(args[4].equals("-f") && args.length >= 6)
					{
						int k = 4;
						bpf = "";
						while(++k < args.length)
							bpf = bpf + " " + args[k];
					}
					else ok = false;
				}
				                           
			}else ok = false;
			
			if(!ok)
			{
				System.out.println("Errore di Sintassi");
				System.out.println("Sintassi: -i networkInterfaceName -o host:port [-f bfpFilter]");
				System.exit(EXIT_FAILURE);
			}
		}
		catch(NumberFormatException e)
		{
			System.out.println("Errore: port deve essere un numero");
			System.out.println("Sintassi: -i networkInterfaceName -o host:port [-f bfpFilter]");
			System.exit(EXIT_FAILURE);
		}
		catch(UnknownHostException e)
		{
			System.out.println("Errore: host fornito non conosciuto");
			System.out.println("Sintassi: -i networkInterfaceName -o host:port [-f bfpFilter]");
			System.exit(EXIT_FAILURE);
		}
		catch(Exception e)
		{
			System.out.println("Errore di Sintassi");
			System.out.println("Sintassi: -i networkInterfaceName -o host:port [-f bfpFilter]");
			System.exit(EXIT_FAILURE);
		}
		
		
		int sysUpTime = (int)(System.currentTimeMillis()/1000);
		registerAtExitHandler();
		
		try 
		{
			ds = new DatagramSocket ();
			Map<String, NetFlow5Record> cache = new HashMap<String, NetFlow5Record>();
			Thread sniffer = new Thread(new Sniffer(cache,bpf,nic)); 
			sniffer.start(); /* avvio il thread sniffer */
			Thread chacheAnalyzer = new Thread(new FlowAnalyzer(cache,sysUpTime,ds));
			chacheAnalyzer.start();	/* avvio il thread analyzer */
		} 
		catch (IOException e) 
		{
			System.out.println("Errore durante la bind del socket");
			System.exit(EXIT_FAILURE);
		}
	}
	/**
	 * Metodo che serve per la creazione di uno ShutdownHook,
	 * per la pulizia delle risorse all'uscita del processo.
	 */
	private static void registerAtExitHandler()
	{
		Runtime.getRuntime().addShutdownHook
		(
			new Thread() 
			{/*libera le risorse : listen socket e active socket*/
			    public void run() 
			    {
			    	if(ds != null)ds.close();
			    }
			}
		);
	}

}
