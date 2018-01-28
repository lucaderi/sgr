import java.io.IOException;
import java.util.*;
import jpcap.*;
import jpcap.packet.*;


/**
 * Classe che implementa un Task: sniffer di rete, il quale cattura i pacchetti
 * dalla scheda di rete e li parsa secondo un formato NetFlow5Record e li inserisce nella
 * memoria cache del processo.
 * @author Francesco
 */
public class Sniffer implements Runnable
{
	private static final int NO_TIMEOUT = 0;
	private static final boolean PROMISC_MODE  = true;
	private static final int BUF_SIZE = 1500;
	
	
	/**
	 * La memoria cache dove sono contenuti i flussi
	 */
	private Map<String, NetFlow5Record> cache;
	/**
	 * Il filtro da applicare alla cattura dei pacchetti
	 */
	private String filter;
	/**
	 * L'interfaccia da cui catturare i pacchetti
	 */
	private String nicName;
	
	/**
	 * Crea un Task Sniffer
	 * @param ht la cache
	 * @param f il filtro
	 */
	public Sniffer(Map<String, NetFlow5Record> ht,String f,String nic)
	{
		this.cache = ht;
		this.filter = f;
		this.nicName = nic;
	}
	/**
	 * Procedura pricipale del task sniffer di rete, 
	 * il quale cattura i pacchetti dalla scheda di rete,
	 * li parsa e li mappa nel formato NetFlow5Record, una volta mappati questi 
	 * sono inseriti nella memoria cache del processo.
	 */
	@Override
	public void run() 
	{
		
		
		
		try 
		{
			NetworkInterface nic = findNIC(nicName);
			if(nic == null)
			{
				System.out.println("Errore scheda di rete:" + Probe.nic + " non trovata");
				System.exit(Probe.EXIT_FAILURE);
			}
			JpcapCaptor driver = JpcapCaptor.openDevice(nic, BUF_SIZE, PROMISC_MODE, NO_TIMEOUT);
			if(filter != null)driver.setFilter(filter, true); /* setto il filtro sulla devide*/
			Packet catPck;
			NetFlow5Record rec;
			for(;;)
			{
				catPck = driver.getPacket();
				if((rec = packetParsing(catPck)) != null)
				{
					updateCache(rec);
				}
				
			}
		} catch (IOException e)
		{
			System.out.println("Errore di I/O durante la cattura dei pacchetti, oppure espressione di filtro errata");
			System.exit(Probe.EXIT_FAILURE);
		}
		
	}
	/**
	 * Questo metodo dato un array di nomi d'interfaccia possibile,
	 * restituisce il reference alla nic di tipo NetworkInterface
	 * @param nameInterface i possibili nomi della scheda di rete che si vuole trovare
	 * @return il reference alla network interface
	 */
	private NetworkInterface findNIC(String nameInterface)
	{
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		String str;
		
		for(int i = 0;i<devices.length;i++)
			if((str = devices[i].description) != null && str.contains(nameInterface))return devices[i];
		for(int i = 0;i<devices.length;i++)
			if((str = devices[i].name) != null && str.contains(nameInterface))return devices[i];
		for(int i = 0;i<devices.length;i++)
			if((str = devices[i].datalink_description) != null && str.contains(nameInterface))return devices[i];
		
		return null;
	}
	/**
	 * Dato uno pacchetto catturato, questo viene parsato e mappato in un NetFlow5Record
	 * @param catPck il pacchetto da parsare
	 * @return il NetFlow5Record opportunamente mappato, null se il pacchetto non è un pacchetto IPv4
	 */
	private NetFlow5Record packetParsing(Packet catPck)
	{
		if(IPv4Parser.isIP(catPck))
		{
			NetFlow5Record rec = new NetFlow5Record();
			IPv4Parser.parser(catPck, rec);
			if(UDPParser.isUDP(catPck))UDPParser.parser(catPck, rec);
			else if(TCPParser.isTCP(catPck))TCPParser.parser(catPck, rec);
			else if(ICMPParser.isIGMP(catPck))ICMPParser.parser(catPck, rec);
			else return null; /*non è riconisciuto*/
			return rec;
		}
		else return null;
	
	}
	/**
	 * Aggiorna la cache, inserendo il NetFlow5Record passato per argomento nella cache
	 * @param rec il NetFlow5Record da inserire
	 */
	private void updateCache(NetFlow5Record rec)
	{
		NetFlow5Record mappedRec;
		synchronized (cache) 
		{
			if((mappedRec = cache.get(rec.getKey())) == null)cache.put(rec.getKey(), rec); /*inserisco un nuovo record */
			else mappedRec.update(rec); /* modifico un record gia' mappato */
		}
		
	}
		
		


}
