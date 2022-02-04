/*
 * state.hpp
 *
 *  Created on: 22/dic/2012
 *      Author: francesco
 */
#ifndef state_hpp
#define state_hpp
using namespace std;
/**
 * Classe che mantiene le informazioni per lo stato dei flussi.
 */
class state{

private:
	int status;
	int nFin;
	int nAck;
	time_t lastPktTime;
public:
	static const int ALLOWED = 1;
	static const int BLOCKED = 0;
	static const int UNKNOWN = 2;
	state(const int st,time_t time){
		this->status = st;
		this->nFin = 0;
		this->nAck = 0;
		this->lastPktTime = time;
	}
	state& operator=(const state& p){
		status = p.status;
		nFin = p.nFin;
		lastPktTime = p.lastPktTime;
		return *this;
	}
	state(const state& p){
		*this = p;
	}
	inline int getStatus() {
		return status;
	}
	inline bool isAllowed(){
		return (status == ALLOWED);
	}
	inline bool isBlocked(){
		return (status == BLOCKED);
	}
	inline bool isUnknown(){
		return (status == UNKNOWN);
	}
	inline void setState(const int st) {
		this->status = st;
	}
	friend std::ostream& operator<<(std::ostream& out,const state& s){
			out << "state =" << s.status;
			return out;
	}
	/**
	 * Aggiorna RecentlySeen
	 */
	inline void updateTime(time_t time){
		lastPktTime = time;
	}
	/**
	* Calcola se il flusso è terminato, rigaurdo la condizione di flusso inattivo
	* @return true se il flusso è terminato, altrimenti false
	*/
	inline bool isInactive(time_t now,int val){
		return ((now - lastPktTime)>val);
	}
	/**
	 * Calcola se il flusso è terminato
	 * @return true se il flusso è terminato, altrimenti false
	 */
	inline bool isClosed(){
		return (  nFin == 2 && nAck > 0 );
	}
	/**
	 * Incrementa il numero di flag fin letti.
	 */
	inline void setFinFlag() {
		nFin++;
	}
	/**
	 * Incrementa il numero degli ack seguenti ai fin letti.
	*/
	inline void setAckOfFinFlag() {
		if(nFin>0)nAck++;
	}
};


#endif



