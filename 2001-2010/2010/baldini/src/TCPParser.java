import jpcap.packet.*;
/**
 * Classe di parsing, che ha la funzione di parsare i pacchetti TCP 
 * catturati attraverso la libreria jpcap e mapparli in record di flusso NetFlow5Record.
 * @author Francesco
 */
public class TCPParser 
{
	private static final byte TCP_CODE = 6;
	/**
	 * Controlla che il pacchetto jpcap sia UDP
	 * @param p il pacchetto jpcap
	 * @return true se il pacchetto è IPv4, false altrimenti
	 */
	public static boolean isTCP(Packet p)
	{
		return (p instanceof TCPPacket);
	}
	/**
	 * Questo metodo mappa un pacchetto jpcap in un pacchetto record netflow5,
	 * settando opportunamente i campi riguardanti il protocollo TCP
	 * @param pck il pacchetto jpcap 
	 * @param rec il record netflow5
	 */
	public static void parser(Packet pck,NetFlow5Record rec)
	{ 
		TCPPacket tcpPkt = (TCPPacket) pck;
		rec.setSrcPort(((short)tcpPkt.src_port));/*porta sorgente*/
		rec.setDstPort(((short)tcpPkt.dst_port));/*porta destinazione*/
		if(tcpPkt.syn)rec.setTcp_flags(NetFlow5Record.SYN);
		if(tcpPkt.rst)rec.setTcp_flags(NetFlow5Record.RST);
		if(tcpPkt.ack)rec.setTcp_flags(NetFlow5Record.ACK);
		if(tcpPkt.fin)rec.setTcp_flags(NetFlow5Record.FIN);
		rec.setProt(TCP_CODE);/*codice di upper layer protocol rispetto a IP*/
	}
}
