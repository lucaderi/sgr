/**
 * 
 */
package flow;

/**
 * Realizza una coda di flussi "expired" utilizzata dal thread Worker
 * 
 * @author dellanna
 *
 */
final class ExpiredQueue {

	private Flow first; //primo elemento coda
	private Flow last; //ultimo elemento coda
	
	
	ExpiredQueue(){
		this.first=this.last=null;
	}
	
	
	Flow getFirst() {
		return first;
	}
	
	
	//rimuove il primo elemento dalla coda; restituisce null se la coda e' vuota
	Flow removeFirst(){
		Flow tmp=first;
		if(first!=null){
			if(!first.equals(last)){//se ci sono due o piu' elementi in coda
				first=first.getNextExpire();
				first.setPreviousExpire(null);
			}else//se un solo elemento in coda
				first=last=null;
			//per questioni di sicurezza nullifica il next di tmp
			tmp.setNextExpire(null);
		}
		return tmp;
	}
	
	
	//remove a tempo O(1) (si deve essere sicuri che flow appartenga alla coda!!)
	void remove (Flow flow){
		if(flow.equals(first)){
			this.removeFirst();
		}else if(flow.equals(last)){
			last=flow.getPreviousExpire();
		}else{
			Flow previous=flow.getPreviousExpire();
			Flow next=flow.getNextExpire();
			previous.setNextExpire(next);
			next.setPreviousExpire(previous);
		}
		
	}
	
	
	Flow getLast() {
		return last;
	}
	
	
	//aggiunge un elemento in fondo alla coda
	void addLast(Flow last) {
		last.setNextExpire(null);
		if(this.last!=null){
			last.setPreviousExpire(this.last);
			this.last.setNextExpire(last);
			this.last = last;
		}else{
			last.setPreviousExpire(null);
			this.first=this.last=last;
		}
	}
	
}
