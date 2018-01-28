/**
 * 
 */
package flow;

import java.util.GregorianCalendar;
import java.util.Locale;
import static java.util.Calendar.*;

/**
 * Questa classe realizza una struttura dati di tipo Flusso.
 * Un flusso e' composto da una parte key che lo identifica univocamente e da una parte "value" a cui sono associati dei valori che posso variare nel tempo.
 * Il flusso e' bidirezionale. Se arriva un pacchetto nella "direzione opposta" non viene creato un altro flusso (e quindi un altra chiave) ma vengono aggiornati
 * i valori del flusso esistente per la direzione opposta.
 * Il flusso puo' puntare ad altri flussi come se fosse un ListNode. Questo permette di realizzare delle code di flussi senza che sia necessario replicare la 
 * struttura dati e quindi sprecare spazio.
 * 
 * @author dellanna
 *
 */
final class Flow {

	//parte "key"
	final byte l4_protocol; //protocollo livello trasporto
	final byte[] src_ip; //indirizzo ip4 sorgente (da header ip)
	final byte[] dst_ip; //indirizzo ip4 destinatario (da header ip)
	final short src_port; //porta sorgente (se procollo e' UDP o TCP)
	final short dst_port; //porta destinatario (se protocoll e' UDP o TCP)
	
	//parte "value"
	long src_dst_byte_rcv; //totale byte ricevuti (direzione: ip_src -> ip_dst)
	long dst_src_byte_rcv; //totale byte ricevuti (direzione: ip_dst -> ip_src) 
	long src_dst_pkt_rcv; //totale pacchetti ricevuti (direzione: ip_src -> ip_dst)
	long dst_src_pkt_rcv; //totale pacchetti ricevuti (direzione: ip_dst -> ip_src) 
	long src_dst_first_timestamp_sec; //timestamp primo pacchetto ricevuto (precisione al secondo) (direzione: ip_src -> ip_dst)
	long src_dst_first_timestamp_usec; //timestamp primo pacchetto ricevuto (precisione al millisecondo) (direzione: ip_src -> ip_dst)
	long src_dst_last_timestamp_sec; //timestamp ultimo pacchetto ricevuto (precisione al secondo) (direzione: ip_src -> ip_dst)
	long src_dst_last_timestamp_usec; //timestamp ultimo pacchetto ricevuto (precisione al millisecondo) (direzione: ip_src -> ip_dst) 
	long dst_src_first_timestamp_sec; //timestamp primo pacchetto ricevuto (precisione al secondo) (direzione: ip_dst -> ip_src)
	long dst_src_first_timestamp_usec; //timestamp primo pacchetto ricevuto (precisione al millisecondo) (direzione: ip_dst -> ip_src)
	long dst_src_last_timestamp_sec; //timestamp ultimo pacchetto ricevuto (precisione al secondo) (direzione: ip_dst -> ip_src)
	long dst_src_last_timestamp_usec; //timestamp primo pacchetto ricevuto (precisione al millisecondo) (direzione: ip_dst -> ip_src)

	//parte listnode
	private volatile Flow next; //puntatore lista tabella hash (il puntatore viene utilizzato anche in FlowQueue)
	private Flow next_expire;//puntatore all' elemento precedente nella coda ExpiredQueue associata
	private Flow previous_expire;//puntatore all' elemento successivo nella coda ExpiredQueue associata
	
	
	/*
	 * Inizializzazione della chiave: i parametri passati identificano la chiave
	 * 
	 * @param l4_protocol
	 * @param src_ip
	 * @param dst_ip
	 * @param src_port
	 * @param dst_port
	 */
	Flow(byte l4_protocol, byte[] src_ip, byte[] dst_ip, short src_port,
			short dst_port) {
		this.l4_protocol = l4_protocol;
		this.src_ip = src_ip;
		this.dst_ip = dst_ip;
		this.src_port = src_port;
		this.dst_port = dst_port;
		//parte listnode
		this.next=null;
		this.next_expire=null;
		this.previous_expire=null;
	}
	
	
	//parte riguardante i puntatori di Flow
	Flow getNext() {
		return next;
	}


	void setNext(Flow next) {
		this.next = next;
	}

	
	Flow getNextExpire() {
		return next_expire;
	}


	void setNextExpire(Flow next_expire) {
		this.next_expire = next_expire;
	}


	Flow getPreviousExpire() {
		return previous_expire;
	}


	void setPreviousExpire(Flow previous_expire) {
		this.previous_expire = previous_expire;
	}
	

	//match chiave nel verso src->dst
	public boolean match(byte l4_protocol,byte[] src_ip,byte[] dst_ip,short src_port,short dst_port){
		if(this.l4_protocol==l4_protocol && 
				this.src_ip[0]==src_ip[0] && this.src_ip[1]==src_ip[1] && this.src_ip[2]==src_ip[2] && this.src_ip[3]==src_ip[3] && 
				this.dst_ip[0]==dst_ip[0] && this.dst_ip[1]==dst_ip[1] && this.dst_ip[2]==dst_ip[2] && this.dst_ip[3]==dst_ip[3] &&
				this.src_port==src_port &&
				this.dst_port==dst_port)
			return true;
		return false;
	}
	
	
	//metodi di visualizzazione dato
	//dati flow restituiti sotto forma di xml e aventi id passati come parametro
	String getXml(long id){
		String string="<f>\n<t>" +
			Protocols.protocol((((short)l4_protocol)&255))+"</t>\n<si>" +
			(((short)src_ip[0])&255)+"."+(((short)src_ip[1])&255)+"."+(((short)src_ip[2])&255)+"."+(((short)src_ip[3])&255)+"</si>\n<di>" +
			(((short)dst_ip[0])&255)+"."+(((short)dst_ip[1])&255)+"."+(((short)dst_ip[2])&255)+"."+(((short)dst_ip[3])&255)+"</di>\n<sp>" +
			(((int)src_port)&65535)+"</sp>\n<dp>"+(((int)dst_port)&65535)+"</dp>\n<sb>"+
			src_dst_byte_rcv+"</sb>\n<sdp>"+src_dst_pkt_rcv+"</sdp>\n";
		GregorianCalendar cal=new GregorianCalendar();
		cal.setTimeInMillis(src_dst_first_timestamp_sec*1000);
		string+="<sf>"+getCal(cal,src_dst_first_timestamp_usec)+"</sf>\n";
		cal.setTimeInMillis(src_dst_last_timestamp_sec*1000);
		string+="<sl>"+getCal(cal,src_dst_last_timestamp_usec)+"</sl>\n";
		if (dst_src_first_timestamp_sec>0) {
			string+="<db>"+dst_src_byte_rcv+"</db>\n<dsp>"+dst_src_pkt_rcv+"</dsp>\n";
			cal.setTimeInMillis(dst_src_first_timestamp_sec*1000);
			string+="<df>"+getCal(cal,dst_src_first_timestamp_usec)+"</df>\n";
			cal.setTimeInMillis(dst_src_last_timestamp_sec*1000);
			string+="<dl>"+getCal(cal,dst_src_last_timestamp_usec)+"</dl>\n";
		}
		return (string+"<i>"+id+"</i>\n</f>\n");
	}
	
	//stato "astratto" oggetto flow
	public String toString() {
		//parte Flow
		String string="CHIAVE:\n";
		string+="	l4_protocol="+Protocols.protocol((((short)l4_protocol)&255));
		string+=" src_ip="+(((short)src_ip[0])&255)+"."+(((short)src_ip[1])&255)+"."+(((short)src_ip[2])&255)+"."+(((short)src_ip[3])&255);
		string+=" dst_ip="+(((short)dst_ip[0])&255)+"."+(((short)dst_ip[1])&255)+"."+(((short)dst_ip[2])&255)+"."+(((short)dst_ip[3])&255);
		string+=" src_port="+(((int)src_port)&65535);
		string+=" dst_port="+(((int)dst_port)&65535)+"\n";
		string+=">>>>> FLOW ROUTE "+(((short)src_ip[0])&255)+"."+(((short)src_ip[1])&255)+"."+(((short)src_ip[2])&255)+"."+(((short)src_ip[3])&255)+" - "+(((short)dst_ip[0])&255)+"."+(((short)dst_ip[1])&255)+"."+(((short)dst_ip[2])&255)+"."+(((short)dst_ip[3])&255)+" >>>>>\n";
		string+="	received bytes="+src_dst_byte_rcv;
		string+="     received packets="+src_dst_pkt_rcv+"\n";
		GregorianCalendar cal=new GregorianCalendar();
		cal.setTimeInMillis(src_dst_first_timestamp_sec*1000);
		string+="	first packet timestamp: "+getCal(cal,src_dst_first_timestamp_usec)+"\n";
		cal.setTimeInMillis(src_dst_last_timestamp_sec*1000);
		string+="	last packet timestamp: "+getCal(cal,src_dst_last_timestamp_usec)+"\n";
		if (dst_src_first_timestamp_sec>0) {
			string += "<<<<< FLOW ROUTE "+(((short)dst_ip[0])&255)+"."+(((short)dst_ip[1])&255)+"."+(((short)dst_ip[2])&255)+"."+(((short)dst_ip[3])&255)+" - "+(((short)src_ip[0])&255)+"."+(((short)src_ip[1])&255)+"."+(((short)src_ip[2])&255)+"."+(((short)src_ip[3])&255)+" <<<<<\n";
			string += "	received bytes=" + dst_src_byte_rcv;
			string += "     received packets=" + dst_src_pkt_rcv + "\n";
			cal.setTimeInMillis(dst_src_first_timestamp_sec * 1000);
			string += "	first packet timestamp: "+getCal(cal,dst_src_first_timestamp_usec)+"\n";
			cal.setTimeInMillis(dst_src_last_timestamp_sec * 1000);
			string += "	last packet timestamp: "+getCal(cal,dst_src_last_timestamp_usec)+"\n";
		}
		return string;
	}
	
	//visualizzazione data
	private String getCal(GregorianCalendar cal,long usec){
		int tmp;
		String string=cal.get(DAY_OF_MONTH)+" "+cal.getDisplayName(MONTH, SHORT, Locale.ENGLISH)+" "+cal.get(YEAR)+" ";
		if((tmp=cal.get(HOUR_OF_DAY))<10)
			string+="0";
		string+=tmp+":";
		if((tmp=cal.get(MINUTE))<10)
			string+="0";
		string+=tmp+":";
		if((tmp=cal.get(SECOND))<10)
			string+="0";
		return string+tmp+"."+usec;
	}
	
}