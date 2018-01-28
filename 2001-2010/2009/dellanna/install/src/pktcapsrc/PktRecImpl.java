import java.net.Inet4Address;
import java.util.GregorianCalendar;
import java.util.Locale;

import static java.util.Calendar.*;

import jpcap.PacketReceiver;
import jpcap.packet.*;

/**
 * 
 */

/**
 * Implementa l'handler di gestione del pacchetto catturato
 * 
 * @author dellanna
 *
 */
public class PktRecImpl implements PacketReceiver {

	private int counter=0;
	
	private final static int TH=4;//lunghezza della tabella hash (20M)
	private final static int TABLE=7;
	/**
	 * @see jpcap.PacketReceiver#receivePacket(jpcap.packet.Packet)
	 */
	@Override
	public void receivePacket(Packet pkt) {
		System.out.println();
		GregorianCalendar cal=new GregorianCalendar();
		cal.setTimeInMillis(pkt.sec*1000);
		System.out.print(counter+") "+cal.get(DAY_OF_MONTH)+" "+cal.getDisplayName(MONTH, SHORT, Locale.ITALY)+" "+cal.get(YEAR)+" "+cal.get(HOUR_OF_DAY)+":"+cal.get(MINUTE)+":"+cal.get(SECOND)+"."+pkt.usec+" pkt len="+pkt.len+" ");
		//se e' un ethernet packet cerca di avanzare nella lettura degli header dei vari livelli dello stack TCP/IP
		if(pkt.datalink instanceof EthernetPacket)
			//src_mac and dst_mac
			System.out.print("src_mac="+((EthernetPacket)pkt.datalink).getSourceAddress().toUpperCase()+" dst_mac="+((EthernetPacket)pkt.datalink).getDestinationAddress().toUpperCase()+" ");
		if(pkt instanceof ARPPacket)
			System.out.print("ARP/RARP PACKET!");
		else if(pkt instanceof IPPacket){
			//source and destination network address
			System.out.print("src_ip="+((IPPacket)pkt).src_ip+" dst_ip="+((IPPacket)pkt).dst_ip+" ");
			//transport layer
			short src_port=0;
			short dst_port=0;
			if(pkt instanceof ICMPPacket)
				System.out.print("ICMP PACKET!");
			else if(pkt instanceof TCPPacket){
				System.out.print("TCP: src_port="+((TCPPacket)pkt).src_port+" dst_port="+((TCPPacket)pkt).dst_port);
				src_port=(short)((TCPPacket)pkt).src_port;
				dst_port=(short)((TCPPacket)pkt).dst_port;
			}
			else if(pkt instanceof UDPPacket){
				System.out.print("UDP: src_port="+((UDPPacket)pkt).src_port+" dst_port="+((UDPPacket)pkt).dst_port);
				src_port=(short)((UDPPacket)pkt).src_port;
				dst_port=(short)((UDPPacket)pkt).dst_port;
			}
			else{
				System.out.print("TRANSPORT LAYER PROTOCOL UNKNOWN!");
			}
			byte l4p=(byte)((IPPacket)pkt).protocol;
			int ip_src=intip((Inet4Address)((IPPacket)pkt).src_ip);
			int ip_dst=intip((Inet4Address)((IPPacket)pkt).dst_ip);
			System.out.print(" hash thread="+hash(l4p,ip_src,ip_dst,src_port,dst_port)+" hash pos="+hash2(l4p,ip_src,ip_dst,src_port,dst_port));
		}else
			System.out.print("NETWORK LAYER PROTOCOL UNKNOWN!");
		System.out.println();
		counter++;
	}

	private static int hash(byte l4_protocol,int ip_src,int ip_dst,short port_src,short port_dst){
		int hash;
		if((hash=((int)l4_protocol)+ip_src+ip_dst+((int)port_src)+((int)port_dst))<0)
			return ~hash%TH;
		return hash%TH;
	}
	
	private static int hash2(byte l4_protocol,int ip_src,int ip_dst,short port_src,short port_dst){
		int hash;
		if((hash=((int)l4_protocol)+ip_src+ip_dst+((int)port_src)+((int)port_dst))<0)
			return ~hash%TABLE;
		return hash%TABLE;
	}
	
	private static int intip(Inet4Address ip){
		byte[] ipbyte=ip.getAddress();
		return (((int)ipbyte[0])&255)*16777216+(((int)ipbyte[1])&255)*65536+(((int)ipbyte[2])&255)*256+(((int)ipbyte[3])&255);
	}
}
