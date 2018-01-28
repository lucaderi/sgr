/*
 * blacklist.hpp
 *
 *  Created on: 28/dic/2012
 *      Author: francesco
 */
#ifndef blacklist_hpp
#define blacklist_hpp

#include <unordered_map>
#include <fstream>
using namespace std;

/*
 * dati per la gestione delle risorse a cui è possibile accedere o meno
 */
class host_list{

private:
	unordered_map<string,bool> db;

public:
	host_list():db(){}
	~host_list(){}
	/**
	 * Restituisce true se la stringa passata come argomento matcha perfettamente,
	 * con almeno  un record della host list: this. altrimenti false.
	 */
	bool query(char* s){
		string str(s);
		unordered_map<string,bool>::iterator it = db.find(str);
		if( it == db.end() )return false;
		return true;
	}
	/**
	 * Aggiunge la stringa s alla struttura
	 */
	inline void add(string& s,bool b){
		db.insert(pair<string,bool>(s,b)).second;
	}
	/**
	 * Carica black list delle url nella db
	 */
	inline bool load(char* filename){
		    ifstream f(filename);
		    string s;
		    if(!f) return false;
		    while( f.good() ) //fino a quando c'è qualcosa da leggere
		    {
		        getline(f, s);//legge tutta la riga dal file e la mette nella variabile s
		        this->add(s,true); //true perchè lo blocco
		    }
		    f.close(); //chiude il file
		    return true;
	}

	friend std::ostream& operator<<(std::ostream& out,const host_list& p){
		unordered_map<string,bool>::const_iterator it;
		for(it = p.db.begin(); it != p.db.end() ; it++)
			out << it->first << " => " << it->second << endl;
		return out;
	}

};


#endif



