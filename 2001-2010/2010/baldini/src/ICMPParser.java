import jpcap.packet.*;
/**
 * Classe di parsing, che ha la funzione di parsare i pacchetti ICMP 
 * catturati attraverso la libreria jpcap e mapparli in record di flusso NetFlow5Record.
 * @author Francesco
 */
public class ICMPParser 
{
	private static final byte ICMP_CODE = 1;
	
	public static boolean isIGMP(Packet p)
	{
		return (p instanceof ICMPPacket);
	}
	/**
	 * Questo metodo mappa un pacchetto jpcap in un pacchetto record netflow5,
	 * settando opportunamente i campi riguardanti il protocollo ICMP
	 * @param pck il pacchetto jpcap 
	 * @param rec il record netflow5
	 */
	public static void parser(Packet pck,NetFlow5Record rec)
	{ 
		ICMPPacket icmpPkt = (ICMPPacket)pck;
		rec.setSrcPort(icmpPkt.type); /* tipo messaggio ICMP */
		rec.setDstPort(icmpPkt.code); /* codice ICMP */
		rec.setProt(ICMP_CODE); /*codice di upper layer protocol rispetto a IP*/
	}
}
