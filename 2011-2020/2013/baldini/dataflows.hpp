/*
 * firewall.hpp
 *
 */
#ifndef firewall_hpp
#define firewall_hpp

#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <functional>
#include "state.hpp"

using namespace std;

/**
 * Identifica un flusso di comunicazione HTTP fra due host
 */
class flow{

private :
	u_int32_t srcaddr;    /* Source IP Address */
	u_int32_t dstaddr;    /* Destination IP Address */
	u_int16_t srcport;    /* TCP/UDP source port number */
	u_int16_t dstport;    /* TCP/UDP destination port number */
	u_int8_t tos;         /* IP Type-of-Service */

public:
	flow(u_int32_t srcaddr,u_int32_t dstaddr,u_int16_t srcport,u_int16_t dstport,u_int8_t tos){
		this->srcaddr = srcaddr;
		this->dstaddr = dstaddr;
		this->srcport = srcport;
		this->dstport = dstport;
		this->tos = tos;
	}
	flow(const flow& p){
		*this = p;
	}
	inline u_int32_t getSrcAddr() const{
		return srcaddr;
	}
	inline u_int32_t getDstAddr() const{
		return dstaddr;
	}
	void set(u_int32_t srcaddr,u_int32_t dstaddr,u_int16_t srcport,u_int16_t dstport,u_int8_t tos){
			this->srcaddr = srcaddr;
			this->dstaddr = dstaddr;
			this->srcport = srcport;
			this->dstport = dstport;
			this->tos = tos;
	}
	bool operator<(const flow& par)const{
		int m1 = min(srcaddr,dstaddr);
		int m2 = min(par.srcaddr,par.dstaddr);
		if(m1 == m2)
		{
			m1 = min(srcport,dstport);
			m2 = min(par.srcport,par.dstport);
			if(m1 == m2)return (tos < par.tos);
			else return (m1 < m2);
		}
		else return(m1 < m2);

	}

	bool operator==(const flow& par)const{
		return
		(
			(srcaddr == par.srcaddr || srcaddr == par.dstaddr)&&
			(dstaddr == par.dstaddr || dstaddr == par.srcaddr)&&
			(srcport == par.srcport || srcport == par.dstport)&&
			(dstport == par.dstport || dstport == par.srcport)&&
			tos == par.tos
		);

	}

	flow& operator=(const flow& p){
		srcaddr=p.srcaddr;
		dstaddr=p.dstaddr;
		srcport=p.srcport;
		dstport=p.dstport;
		tos=p.tos;
		return *this;
	}
	friend std::ostream& operator<<(std::ostream& out,const flow& p){
		struct in_addr in;
		struct in_addr in2;
		in.s_addr =  htonl(p.srcaddr);
		in2.s_addr = htonl(p.dstaddr);
		char buf[20];
		strcpy(buf,inet_ntoa(in));
		out << "Source Ip: "<< buf  << " - Destination Ip: " << inet_ntoa(in2) << " ports = "<<p.srcport<<":"<<p.dstport;
		return out;
	}
};
/**
 * Necessario fornire la funzione hash relativa alla classe flow per la libreria std::unordered_map
 */
namespace std {
template <>
class hash<flow> {
 public:
	 size_t operator()(const flow& f) const { return ( f.getSrcAddr() ^ f.getDstAddr() ); }
};
}
/**
 * Necessario fornire la funzione di comparazione fra chiavi,
 * relativa alla classe flow per la libreria std::unordered_map
 */
namespace std {
template <>
class equal_to<const flow>{
 public:
	bool operator() (const flow& x, const flow& y){return x==y;}
};
}

/**
 * Numero di Bucket da allocare alla creazione della Mappa
 */
#define INITIAL_BUCKETS 256
/**
 * Classe che ha lo scopo di implementare una mappa fra flussi
 * ed il relativo stato associato flusso
 */
class data_flows{
private:
	unordered_map<flow,state> flows;

public:

	data_flows():flows(INITIAL_BUCKETS){}
	~data_flows(){}

	/**
	 * aggiunge un nuovo record di flusso con stato di passo sconosciuto
	 */
	inline bool add_new_flow(flow& f,state& s){
		return flows.insert(pair<flow,state>(f,s)).second;
	}
	/**
	* blocca il flusso f
	*/
	inline bool block(flow& f){
		unordered_map<flow,state>::iterator it;
		it = flows.find(f);
		if(it == flows.end())return false;
		it->second.setState(state::BLOCKED);
		return true;
	}
	/**
	* permette al flusso f di passare
	*/
	inline bool allow(flow& f){
		unordered_map<flow,state>::iterator it = flows.find(f);
		if(it == flows.end())return false;
		it->second.setState(state::ALLOWED);
		return true;
	}
	inline pair<flow*,state*>* getState(flow& f,pair<flow*,state*>* pbuf){
		unordered_map<flow,state>::iterator it = flows.find(f);
		if( it == flows.end() )return NULL;
		pbuf->first = (flow*) &it->first;
		pbuf->second = &it->second;
		return pbuf;
	}
	/**
	 * Rimuove il flusso f dalla struttura
	 */
	inline bool remove(const flow& f){
		return flows.erase(f);
	}
	inline unordered_map<flow,state>* getMap(){
		return &flows;
	}
	friend std::ostream& operator<<(std::ostream& out,const data_flows& d){
		unordered_map<flow,state>::const_iterator it;
		for(it = d.flows.begin(); it !=  d.flows.end(); it++)
			out << it->first << " => "<< it->second << endl;
		return out;
	}

};


#endif
/*

int main(){

	firewall f;

	cout << f.db_add_firewall_block("ciao") <<endl;
	cout << f.db_add_firewall_block("juve") <<endl;
	cout << f.db_add_firewall_block("ciao") <<endl;
	cout << f.db_add_firewall_block("barsa") <<endl;
	cout << "è permesso ? " << f.db_query("ciao") <<endl;
	cout << "è permesso ? " << f.db_query("alo") <<endl;
	cout << "è permesso ? " << f.db_query("juve") <<endl;

	flow p[5];
	for(int i=0;i<5;i++){
		p[i].set(i,i+1,9,80,0);
		cout << p[i] << endl;
		cout << "flusso creato, risultato: " <<f.add_new_flow(p[i])<<endl;

	}
	for(auto i:f.flows_status)
		cout << i.first << " - " << i.second << endl;
	cout << "============================================"<<endl;
	cout << "flusso bloccato, risultato: " <<f.block_flow(p[0])<<endl;;
	cout << "flusso bloccato, risultato: " <<f.block_flow(p[2])<<endl;;

	flow fx(4,5,9,80,0);
	f.block_flow(fx);
	for(auto i:f.flows_status)
			cout << i.first << " - " << i.second << endl;
	cout << "============================================"<<endl;
	f.remove_flow(fx);
	f.remove_flow(p[1]);
	for(auto i:f.flows_status)
		cout << i.first << " - " << i.second << endl;


	return 0;
}
*/
