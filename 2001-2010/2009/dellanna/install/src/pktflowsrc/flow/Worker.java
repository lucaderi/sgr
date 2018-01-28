/**
 * 
 */
package flow;

import java.net.Inet4Address;
import jpcap.packet.*;


/**
 * Questa classe realizza il fulcro di pktflow. Infatti il thread legge pacchetti dalla sua coda PacketQueue, genera flussi, li inserisce nella tabella HashFlow
 * e gestisce una politica di rimozione di flussi dalla tabella hash utilizzando una coda di "expire" 
 * 
 * @author dellanna
 *
 */
final class Worker extends Thread {

	private final PacketQueue pkt_queue; //coda di pacchetti (inviati ai worker)
	private final FlowQueue flow_queue; //coda di flussi inviati al Collector
	private final HashFlow hashtable; //tabella hash comune a tutti i worker in cui salvare i flussi
	private final int flow_ttl; //Flow time to live: tempo di vita massima flusso (5 min)
	private final int flow_inactivity; //tempo massimo di inattivita' flusso (15 sec)


	/*
	 * @param pkt_queue: riferimento alla coda di pacchetti ricevuti da PacketDispatcher
	 * @param flow_queue: riferimento alla coda di flussi inviati al Collector
	 * @param htable: riferimento alla tabella hash cui aggiornare/creare flusi
	 * @param flow_ttl: tempo di vita massimo flusso
	 * @param flow_inactivity: tempo di inattivita' massimo flusso
	 */
	Worker(PacketQueue pkt_queue, FlowQueue flow_queue, HashFlow hashtable, int flow_ttl, int flow_inactivity) {
		this.pkt_queue = pkt_queue;
		this.flow_queue = flow_queue;
		this.hashtable = hashtable;
		this.flow_ttl = flow_ttl;
		this.flow_inactivity = flow_inactivity;
	}


	//corpo del thread
	public void run(){
		Packet pkt;
		Flow flow;
		ExpiredQueue expired_queue=new ExpiredQueue(); //coda dei pacchetti "expired"
		boolean flag1,flag2;//flags di attivita'
		while(true){
			flag1=flag2=false;//inizializza i flags
			while((pkt=pkt_queue.getPacket())!=null){
				flag1=true;//si sta svolgendo un attivita' di acquisizione pkt
				if(pkt.len<34)//se il pkt e' minore di 34 byte non puo' aver catturato un IPPacket v4 valido quindi lo scarta
					continue;//va all'iterazione successiva
				if (pkt instanceof TCPPacket){//se e' un pacchetto tcp
					TCPPacket pkt2=(TCPPacket)pkt;
					//se e' un pkt mirror lo scarta
					if(pkt2.src_ip!=pkt2.dst_ip || pkt2.src_port!=pkt2.dst_port)
						hashtable.update((byte)6,//TCP
								((Inet4Address)pkt2.src_ip).getAddress(),
								((Inet4Address)pkt2.dst_ip).getAddress(),
								(short)pkt2.src_port,
								(short)pkt2.dst_port,
								pkt2.len,
								pkt2.sec,
								pkt2.usec,
								expired_queue);
				}else if (pkt instanceof UDPPacket){//se e' un pacchetto udp
					UDPPacket pkt2=(UDPPacket)pkt;
					//se e' un pkt mirror lo scarta
					if(pkt2.src_ip!=pkt2.dst_ip || pkt2.src_port!=pkt2.dst_port)
						hashtable.update((byte)17,//UDP
								((Inet4Address)pkt2.src_ip).getAddress(),
								((Inet4Address)pkt2.dst_ip).getAddress(),
								(short)pkt2.src_port,
								(short)pkt2.dst_port,
								pkt2.len,
								pkt2.sec,
								pkt2.usec,
								expired_queue);
				}else if (pkt instanceof IPPacket){//se e' un pacchetto qualsiasi
					IPPacket pkt2=(IPPacket)pkt;
					hashtable.update((byte)pkt2.protocol,// protocollo di trasporto generico
							((Inet4Address)pkt2.src_ip).getAddress(),
							((Inet4Address)pkt2.dst_ip).getAddress(),
							(short)0,
							(short)0,
							pkt2.len,
							pkt2.sec,
							pkt2.usec,
							expired_queue);
				}
			}//fine while
			//scorre la coda expired_queue per vedere se ci sono flussi expired
			flow=expired_queue.getFirst();
			long time=System.currentTimeMillis();
			if (flow!=null) {
				if (flow.src_dst_first_timestamp_sec*1000+flow_ttl<time || flow.src_dst_last_timestamp_sec*1000+flow_inactivity<time
						|| (flow.dst_src_last_timestamp_sec > 0 && flow.dst_src_last_timestamp_sec
								* 1000 + flow_inactivity < time)) {
					flag2 = true;//si sta svolgendo un attivita' di rimozione flusso
					expired_queue.removeFirst(); //rimuove il flusso dalla coda expired
					hashtable.flush(flow.l4_protocol, flow.src_ip, flow.dst_ip,flow.src_port, flow.dst_port);//rimuove il flusso dalla tabella hash
					//invia il flusso al collector
					flow_queue.addLast(flow);
				}
			}
			//se in questo ciclo di esecuzione non e' stata svolta alcuna attivita' il thread va in attesa attiva
			if(flag1==false && flag2==false)
				Thread.yield();
		}
	}	
}
