/**
 * 
 */
package flow;


/**
 * Questa classe implementa una struttura dati di tipo hash in cui vengono salvati i flussi di rete: ossia le coppie (Key,Value)
 * I flussi sono bidirezionali
 * 
 * @author dellanna
 *
 */
final class HashFlow {
	
	private final int THASH_SIZE; //lunghezza della tabella hash
	
	private Flow[] hashtable; //tabella hash di flussi
	
		
	//size: inizializza la dimensione della tabella hash
	HashFlow(int size) {
		//inizializza tabella
		THASH_SIZE=size;
		this.hashtable=new Flow[THASH_SIZE];
	}


	//aggiorna o crea un flusso
	void update(
			//parte "key" (del pacchetto catturato)
			byte l4_protocol, //protocollo livello trasporto
			byte[] src_ip, //indirizzo ip4 sorgente (da header ip)
			byte[] dst_ip, //indirizzo ip4 destinatario (da header ip)
			short src_port, //porta sorgente (se procollo e' UDP o TCP)
			short dst_port, //porta destinatario (se protocoll e' UDP o TCP)
			//parte value (del pacchetto catturato)
			int byte_rcv, //totale byte ricevuti  
			long timestamp_sec, //timestamp pacchetto catturato (precisione al secondo)
			long timestamp_usec, //timestamp pacchetto catturato (precisione al millisecondo)
			ExpiredQueue expired_queue //riferimento alla coda dei pacchetti expired del thread in esecuzione corrente
	){
		//calcola funzione hash
		int hash=hash(l4_protocol,src_ip,dst_ip,src_port,dst_port);
		
		Flow flow;
		//se c'e' una collisione inizia a scorrere la lista
		if((flow=this.hashtable[hash])!=null)
			do{
				//se la chiave e' presente aggiorna il flusso
				//viene calcolato il verso del flusso e vengono aggiornati i valori a seconda del verso
				//verso src->dst
				if( flow.match(l4_protocol, src_ip, dst_ip, src_port, dst_port)){
					flow.src_dst_byte_rcv+=byte_rcv;
					flow.src_dst_pkt_rcv++;
					flow.src_dst_last_timestamp_sec=timestamp_sec;
					flow.src_dst_last_timestamp_usec=timestamp_usec;
					//aggiorna il flusso
					expired_queue.remove(flow);
					expired_queue.addLast(flow);
					return;	
				}
				//verso dst->src
				if( flow.match(l4_protocol, dst_ip, src_ip, dst_port, src_port)){
					flow.dst_src_byte_rcv+=byte_rcv;
					flow.dst_src_pkt_rcv++;
					flow.dst_src_last_timestamp_sec=timestamp_sec;
					flow.dst_src_last_timestamp_usec=timestamp_usec;
					if(flow.dst_src_first_timestamp_sec==0){//se e' il primo pacchetto che arriva in direzione dst->src
						flow.dst_src_first_timestamp_sec=timestamp_sec;
						flow.dst_src_first_timestamp_usec=timestamp_usec;
					}
					//aggiorna il flusso
					expired_queue.remove(flow);
					expired_queue.addLast(flow);
					return;	
				}	
			}while((flow=flow.getNext())!=null);//scorre la lista
		
		//se non ha trovato la chiave vuol dire che non esiste, quindi crea un nuovo flusso e lo inserisce sia nella sua lista all'interno della tabella hash
		//sia nella coda "expire"
		//crea il flusso
		flow=new Flow(l4_protocol,src_ip,dst_ip,src_port,dst_port);
		flow.src_dst_last_timestamp_sec=flow.src_dst_first_timestamp_sec=timestamp_sec;
		flow.src_dst_last_timestamp_usec=flow.src_dst_first_timestamp_usec=timestamp_usec;
		flow.src_dst_byte_rcv=byte_rcv;
		flow.src_dst_pkt_rcv=1;
		//inserisce il flusso nella tabella hash gestita da tutti i threads
		flow.setNext(this.hashtable[hash]);
		this.hashtable[hash]=flow;
		//inserisce il flusso nella coda expire appartenente al solo thread che la gestisce
		expired_queue.addLast(flow);
	}

	
	//esporta il flusso identificato dai parametri "key" forniti al metodo se non e' presente lancia NullpointerException
	Flow flush(
			byte l4_protocol, //protocollo livello trasporto
			byte[] src_ip, //indirizzo ip4 sorgente (da header ip)
			byte[] dst_ip, //indirizzo ip4 destinatario (da header ip)
			short src_port, //porta sorgente (se procollo e' UDP o TCP)
			short dst_port //porta destinatario (se protocoll e' UDP o TCP)
	){
		//calcola funzione hash e genera un iteratore sulla lista trovata
		int hash=hash(l4_protocol,src_ip,dst_ip,src_port,dst_port);
		
		Flow precursor=null;
		Flow flow=this.hashtable[hash];
		do{
			//se la chiave e' presente aggiorna il flusso
			if(flow.match(l4_protocol, src_ip, dst_ip, src_port, dst_port)){
				if(precursor==null)//se e' il primo elemento della lista ad essere cancellato
					this.hashtable[hash]=flow.getNext();
				else
					precursor.setNext(flow.getNext()); 
				//per sicurezza nullifica il next di flow
				flow.setNext(null);
				return flow; //una volta "consumato" il garbage collector pensera' a cancellare in seguito l'oggetto se non e' piu' utilizzato
			}//fine if
			//aggiorna precursor
			precursor=flow;
		}while((flow=flow.getNext())!=null);//scorre la lista
		
		throw new NullPointerException();
	}
	
	void setHash(Flow flow){
		this.hashtable[hash(flow.l4_protocol, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port)]=flow;
	}
	
	Flow tmp(int i){
		return this.hashtable[i];
	}

	
	//funzione hash per calcolare la posizione del flow all'interno della tabella hash
	private int hash(byte l4_protocol,byte[] src_ip,byte[] dst_ip,short src_port,short dst_port){
		int hash;
		int ips=(((int)src_ip[0])&255)*16777216+(((int)src_ip[1])&255)*65536+(((int)src_ip[2])&255)*256+(((int)src_ip[3])&255);
		int ipd=(((int)dst_ip[0])&255)*16777216+(((int)dst_ip[1])&255)*65536+(((int)dst_ip[2])&255)*256+(((int)dst_ip[3])&255);
		if((hash=((int)l4_protocol)+ips+ipd+((int)src_port)+((int)dst_port))<0)
			return hash=~hash%THASH_SIZE;
		return hash=hash%THASH_SIZE;
	}
	
}
