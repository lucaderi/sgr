import jpcap.packet.*;
/**
 * Classe di parsing, che ha la funzione di parsare i pacchetti UDP 
 * catturati attraverso la libreria jpcap e mapparli in record di flusso NetFlow5Record.
 * @author Francesco
 */
public class UDPParser 
{
	private static final byte UDP_CODE = 17;
	/**
	 * Controlla che il pacchetto jpcap sia UDP
	 * @param p il pacchetto jpcap
	 * @return true se il pacchetto è IPv4, false altrimenti
	 */
	public static boolean isUDP(Packet p)
	{
		return (p instanceof UDPPacket);
	}
	/**
	 * Questo metodo mappa un pacchetto jpcap in un pacchetto record netflow5,
	 * settando opportunamente i campi riguardanti il protocollo UDP
	 * @param pck il pacchetto jpcap 
	 * @param rec il record netflow5
	 * 
	 */
	public static void parser(Packet pck,NetFlow5Record rec)
	{
		UDPPacket udpPkt = (UDPPacket)pck;
		rec.setSrcPort(((short)udpPkt.src_port));/*porta sorgente*/
		rec.setDstPort(((short)udpPkt.dst_port));/*porta destinazione*/
		rec.setProt(UDP_CODE);/*codice di upper layer protocol rispetto a IP*/
	}
}
