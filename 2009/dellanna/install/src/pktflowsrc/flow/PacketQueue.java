/**
 * 
 */
package flow;

import java.util.concurrent.atomic.AtomicInteger;

import jpcap.packet.Packet;

/**
 * Questa classe implementa una coda non sincronizzata di pacchetti. Se la coda e' piena i pacchetti vengono scartati. Non viene implementata alcuna politica di
 * attesa o di notifica. la coda prende in considerazione solo il caso: 1 produttore -> 1 consumatore
 * 
 * Questa coda viene utilizzata dal PacketDispatcher e dal Worker corrispondente
 * 
 * @author dellanna
 *
 */
final class PacketQueue {

	private final int MAX_LENGTH; // lunghezza massima coda 
	private AtomicInteger size; // quanti elementi in coda (varibile atomica gli incrementi o decrementi vengono effettuati utilizzando la tecnologia CAS ) 
	private int head;// testa della coda
	private int tail;// ultima posizione coda: init -1 per inizializzare situazione di coda vuota
	private Packet[] queue; // coda fisica di pacchetti
	private Packet tmp; // temporaneo 
	
	
	//size: Inizializza coda passando length come dimensione iniziale
	PacketQueue(int size) {
		MAX_LENGTH=size;
		this.size=new AtomicInteger();
		head=0;
		tail=-1;
		queue=new Packet[MAX_LENGTH];
	}	

	
	//inserisce pacchetti in coda, se la coda e'piena li scarta
	void insertPacket(Packet pkt){
		if(size.get()<MAX_LENGTH){
			//inserisce elementi in fondo alla coda aggiornando correttamente i puntatori
		    tail=(tail+1)%MAX_LENGTH;
		    queue[tail]=pkt;
		    //modifica atomica della variabile size
		    size.incrementAndGet();
		}
	}
	  
	
	//prende pacchetti dalla coda, se la coda e'vuota restituisce null 
	Packet getPacket() {
	    
		if(size.get()>0){
			//consuma pacchetti dalla testa della coda
		    tmp=queue[head];
		    head=(head+1)%MAX_LENGTH;
		    //modifica atomica della variabile size
		    size.decrementAndGet();
		    return tmp;
		}
		return null;
	}
	
}