/**
 * 
 */
package flow;


/**
 * Questa classa realizza una versione semplificata della coda ExpiredQueue, ma gestisce il problema della coda condivisa tra un produttore e un consumatore
 * utilizzando algoritmi wait/lock free. 
 * 
 * Questa coda viene utilizzata da un Worker e dal Collector
 * 
 * @author dellanna
 *
 */
final class FlowQueue {
	private volatile Flow precursor_first; //antecedente al primo elemento in coda 
	private volatile Flow first; //primo elemento coda
	private volatile Flow last; //ultimo elemento coda
	
	
	FlowQueue(){
		this.first=this.last=null;
		byte[] ip1={0,0,0,0};
		this.precursor_first=new Flow((byte)0,ip1,ip1,(short)0,(short)0);//dummy node
	}
	
	
	//rimuove il primo elemento dalla coda; restituisce null se la coda e' vuota
	Flow removeFirst(){
		
		if(this.first!=null){
			this.precursor_first=this.first;
			this.first=this.first.getNext();
			return this.precursor_first;
		}
		this.first=this.precursor_first.getNext();
		return null;
	}
	
	
	//aggiunge un elemento in fondo alla coda
	void addLast(Flow flow){
		flow.setNext(null);
		if(this.last!=null)
			this.last.setNext(flow);
		else
			this.precursor_first.setNext(flow);
		this.last=flow;
	}
	
	
	Flow getFirst() {
		return this.first;
	}
	
	
	Flow getLast() {
		return this.last;
	}

}
