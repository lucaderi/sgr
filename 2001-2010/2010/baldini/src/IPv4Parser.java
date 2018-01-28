


import jpcap.packet.*;
/**
 * Classe di parsing, che ha la funzione di parsare i pacchetti IPv4 
 * catturati attraverso la libreria jpcap e mapparli in record di flusso NetFlow5Record.
 * @author Francesco
 */
public class IPv4Parser 
{
	/**
	 * Controlla che il pacchetto jpcap sia IPv4
	 * @param p il pacchetto jpcap
	 * @return true se il pacchetto è IPv4, false altrimenti
	 */
	public static boolean isIP(Packet p)
	{
		return (p instanceof IPPacket && ((IPPacket)p).version==4);
	}
	/**
	 * Questo metodo mappa un pacchetto jpcap in un pacchetto record netflow5,
	 * settando opportunamente i campi riguardanti il protocollo IPv4
	 * @param pck il pacchetto jpcap 
	 * @param rec il record netflow5
	 */
	public static void parser(Packet pck,NetFlow5Record rec)
	{
		IPPacket ipPkt = (IPPacket)pck;
		rec.setSrcAddr(strToIp(ipPkt.src_ip.getHostAddress()));  /*IP sorgente*/
		rec.setDstAddr(strToIp(ipPkt.dst_ip.getHostAddress()));  /*IP destinazione*/
		rec.setTos(ipPkt.rsv_tos);     /*TOS*/
		rec.setFirst((int)(System.currentTimeMillis()/1000)); /*Tempo inizio flusso*/
		rec.setLast((int)(System.currentTimeMillis()/1000));  /*Tempo fine flusso*/
		rec.setDPkts(1);  /*Numero pacchetti del flusso*/
		rec.setDOctets(ipPkt.len);  /*numero di byte del flusso non consederando i byte del livello datalink*/
	}
	/**
	 * Converte un ip in dotted form in un ip su 32bit
	 * @param ipDottedForm ip in formato di stringa
	 * @return l'ip in formato su 32 bit
	 */
	public static int strToIp(String ipDottedForm) throws NumberFormatException
	{
		String buf[] = ipDottedForm.split("[.]");
		int ip = 0;
		ip+= (Integer.parseInt(buf[0]) << 24) ;
		ip+= (Integer.parseInt(buf[1]) << 16) ; 
		ip+= (Integer.parseInt(buf[2]) << 8) ;
		ip+= Integer.parseInt(buf[3]);
		return ip;
	}
	/**
	 * Converte un ip su 32bit in un ip in dotted form 
	 * @param ip l'ip in formato su 32 bit
	 * @return ip in formato di stringa
	 */
	public static String ipToStr(int ip) 
	{
		String s = "";
		s = s + ((ip >> 24) & 0xFF ) + "."; 
		s = s + ((ip >> 16) & 0xFF ) + ".";
		s = s + ((ip >> 8) & 0xFF ) + ".";
		s = s + (ip & 0xFF );
		return s;
	}
}
