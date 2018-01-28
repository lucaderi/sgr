/**
 * 
 */
package flow;

import java.net.Inet4Address;
import java.util.Timer;
//import java.util.concurrent.ConcurrentLinkedQueue;

import jpcap.PacketReceiver;
import jpcap.packet.*;

/**
 * Questa classe riceve i pacchetti sniffati da pcap e li instrada in una determinata coda PacketQueue a seconda della funzione hash calcolata.
 * La classe inizializza pure i threads Worker, il thread Collector e tutte le code necessarie per mettere in comunicazione questi threads
 * Inizializza il timer associato a RRDUpdateTask in modo da permettere l'aggiornamento periodico dell'RRD associato a Packet Flow
 * 
 * @author dellanna
 *
 */
public final class PacketDispatcher implements PacketReceiver {

	private static int THASH_SIZE=20971520;//lunghezza della tabella hash (20M)
	private static int PKT_QUEUE_SIZE=524288;//lunghezza della coda pkt_queue(512K)
	private static int WORKER_SIZE=0;//numero dei worker e delle code utilizzate
	private static int FLOW_TTL=300000;//Flow time to live: tempo di vita massima flusso (5 min)
	private static int FLOW_INACTIVITY=15000;//tempo massimo di inattivita' flusso (15 sec)
	private static boolean CHOICE=true; // a seconda della scelta il collector stampa a video i flussi o li scrive nel last.xml che sara' letto da pktflow.html
	private static long RRD_TIMER=60000;//timer utilizzato per aggiornare periodicamente dati relativi a flussi in un Round Robin Database.
	private static String RRD_FILE="flows.rrd";//file in cui e' salvato il Round Robin Database che gestisce i dati riguardanti i flussi ricevuti
	private static String GRAPH_HOUR="./pktflowgui/graphs/graph_hour.png";//file in cui e' salvato il grafico dei flussi per ora
	private static String GRAPH_DAY="./pktflowgui/graphs/graph_day.png";//file in cui e' salvato il grafico dei flussi per giorno
	private PacketQueue[] pkt_queue; //code dei pacchetti (inviati ai worker)
	
	
	//inizializza il Dispatcher caricando il profilo di default
	public PacketDispatcher(){
		this.init();
	}
	
	
	//inizializza il Dispatcher caricando il profilo passato attraverso i parametri
	public PacketDispatcher(int thash_size,int pkt_queue_size,int worker_size,int flow_ttl,int flow_inactivity,boolean choice) {
		//inizializza esplicitamente le variabili utilizzate in Packet Flow
		if(thash_size>0)
			THASH_SIZE=thash_size*1024;//lunghezza della tabella hash (in K)
		if(pkt_queue_size>0)
			PKT_QUEUE_SIZE=pkt_queue_size*1024;//lunghezza della coda pkt_queue(in K)
		if(worker_size>0)
			WORKER_SIZE=worker_size;//numero dei worker e delle code utilizzate
		if(flow_ttl>0)
			FLOW_TTL=flow_ttl*1000;//Flow time to live: tempo di vita massima flusso (in sec)
		if (flow_inactivity>0)
			FLOW_INACTIVITY=flow_inactivity*1000;//tempo massimo di inattivita' flusso (in sec)
		CHOICE=choice;
		this.init();
	}


	//routine eseguita da JpcapCaptor.processPacket una volta che riceve un pacchetto dai livelli sottostanti del sistema
	public void receivePacket(Packet pkt) {
		//calcola la funzione hash del pacchetto e lo instrada nella coda opportuna
		if (pkt instanceof TCPPacket){//se e' un pacchetto tcp
			TCPPacket pkt2=(TCPPacket)pkt;
			pkt_queue[hash((byte)6,((Inet4Address)pkt2.src_ip).getAddress(),((Inet4Address)pkt2.dst_ip).getAddress(),(short)pkt2.src_port,(short)pkt2.dst_port)].insertPacket(pkt);
		}else if (pkt instanceof UDPPacket){//se e' un pacchetto udp
			UDPPacket pkt2=(UDPPacket)pkt;
			pkt_queue[hash((byte)17,((Inet4Address)pkt2.src_ip).getAddress(),((Inet4Address)pkt2.dst_ip).getAddress(),(short)pkt2.src_port,(short)pkt2.dst_port)].insertPacket(pkt);
		}else if (pkt instanceof IPPacket){//se e' un pacchetto qualsiasi
			IPPacket pkt2=(IPPacket)pkt;
			pkt_queue[hash((byte)pkt2.protocol,((Inet4Address)pkt2.src_ip).getAddress(),((Inet4Address)pkt2.dst_ip).getAddress(),(short)0,(short)0)].insertPacket(pkt);
		}
	}

	
	//metodo privato di init
	private void init(){
		//inizializza WORKER_SIZE al numero di processori presenti sulla macchina
		if(WORKER_SIZE<=0)
			WORKER_SIZE=Runtime.getRuntime().availableProcessors();
		//se il numero di thread non e' un multiplo di thash_size interrompe l'esecuzione del programma 
		if(THASH_SIZE%WORKER_SIZE!=0)
			throw new IllegalArgumentException("WARNING! Hash table size doesn't fit worker size! closing...");
		//stampa a video il setup caricato
		System.out.println();
		System.out.println("Setup loaded:");
		System.out.println("	Hash table size= "+THASH_SIZE+" Bytes");
		System.out.println("	Packet Queues size= "+PKT_QUEUE_SIZE+" Bytes");
		System.out.println("	Available worker threads= "+WORKER_SIZE);
		System.out.println("	Flow time to live= "+FLOW_TTL+" millisec");
		System.out.println("	Max Flow inactivity time= "+FLOW_INACTIVITY+" millisec");
		System.out.println("	Flow printed in flows.xml? "+CHOICE);
		System.out.println("	RRD update time= "+RRD_TIMER+" millisec");
		System.out.println("	RRD file= "+RRD_FILE);
		System.out.println("	Flow graph per hour file= "+GRAPH_HOUR);
		System.out.println("	Flow graph per day file= "+GRAPH_DAY);
		System.out.println();
		//inizializza la tabella hash
		HashFlow hashtable=new HashFlow(THASH_SIZE);
		//inizializza le altre strutture dati
		this.pkt_queue=new PacketQueue[WORKER_SIZE];
		FlowQueue[] flow_queue=new FlowQueue[WORKER_SIZE];
		Worker[] worker = new Worker[WORKER_SIZE];
		//inizializza le code di flussi
		for (int i=0;i<WORKER_SIZE;i++)
			flow_queue[i]=new FlowQueue();	
		//inizializza il collector
		Collector collector= new Collector(flow_queue,CHOICE);
		collector.start();
		for (int i=0;i<WORKER_SIZE;i++){
			//inizializza le code di pacchetti
			pkt_queue[i]=new PacketQueue(PKT_QUEUE_SIZE);
			//inizializza i worker
			worker[i]=new Worker(pkt_queue[i],flow_queue[i],hashtable,FLOW_TTL,FLOW_INACTIVITY);
			worker[i].start();
		}
		//inizializza il timer e il task per effettuare l'update del RRD
		try {
			new Timer().scheduleAtFixedRate(new RRDUpdateTask(collector,RRD_FILE,GRAPH_HOUR,GRAPH_DAY), RRD_TIMER, RRD_TIMER);
		} catch (Exception e) {
			System.err.println(e+" Error! Flows won't be loaded on "+RRD_FILE);
		}
	}
	
	
	//funzione hash per calcolare la posizione del flow all'interno della tabella hash
	private static int hash(byte l4_protocol,byte[] src_ip,byte[] dst_ip,short src_port,short dst_port){
		int hash;
		int ips=(((int)src_ip[0])&255)*16777216+(((int)src_ip[1])&255)*65536+(((int)src_ip[2])&255)*256+(((int)src_ip[3])&255);
		int ipd=(((int)dst_ip[0])&255)*16777216+(((int)dst_ip[1])&255)*65536+(((int)dst_ip[2])&255)*256+(((int)dst_ip[3])&255);
		if((hash=((int)l4_protocol)+ips+ipd+((int)src_port)+((int)dst_port))<0)
			return ~hash%WORKER_SIZE;
		return hash%WORKER_SIZE;
	}
}
