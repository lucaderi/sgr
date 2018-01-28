/*
 * flussi.cpp
 */

#include "flussi.hpp"

flussi::flussi() //costruttore
{
	arrayFlussi = new flusso[nFlussi];
}

flussi::~flussi()
{
	boost::mutex::scoped_lock lock(f_mutex);
	portsTcp.clear();
	portsUdp.clear();
	indiciAttivi.clear();
	delete arrayFlussi;
}

int flussi::hash(struct in_addr ipM, struct in_addr ipD, unsigned int pM, unsigned int pD, bool protocol)
{
	int prot;
	if (protocol)
		prot = 0;
	else
		prot = 1;
	return (ipM.s_addr + ipD.s_addr + pM + pD + prot) % nFlussi;
}

void flussi::addFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol)
{
	boost::mutex::scoped_lock lock(f_mutex);
	boost::xtime_get(&xt, boost::TIME_UTC);
	int i = hash(ipM, ipD, portM, portD, protocol);
	if (arrayFlussi[i].nPacchetti != 0)//collisione
	{
		//cout << "F - Collisione hash (id: " << i << ") sovrascrivo" << endl;
	}
	if (protocol) //tcp
	{
		//cout << "F - Flusso TCP aggiunto (id: " << i << ")" << endl;
		arrayFlussi[i].ipM = ipM;
		arrayFlussi[i].ipD = ipD;
		arrayFlussi[i].portaM = portM;
		arrayFlussi[i].portaD = portD;
		arrayFlussi[i].protocol = protocol;
		arrayFlussi[i].lastUpdate = xt.sec; //aggiorno data ultimo update
		arrayFlussi[i].nPacchetti = 1;
	}
	else //Udp
	{
		/*Non esistendo flussi nel protocollo udp accomuno tutti i pacchetti con gli stessi dati per creare uno pseudo-flusso, e confronto
		 *la porta sorgente e la porta destinazione con quelle che conosco, se almeno una delle due  riconosciuta quella  la porta di destinazione
		 *utile per identificare il protocollo.
		 */
		//cout << "F - Flusso UDP aggiunto (id: " << i << ")" << endl;
		if (portToProtocoll(portD).compare("Unknown") != 0) //protocollo associato a portD conosciuto
		{
			arrayFlussi[i].ipM = ipM;
			arrayFlussi[i].ipD = ipD;
			arrayFlussi[i].portaM = portM;
			arrayFlussi[i].portaD = portD;
			arrayFlussi[i].protocol = protocol;
			arrayFlussi[i].lastUpdate = xt.sec; //aggiorno data ultimo update
			arrayFlussi[i].nPacchetti = 1;
		}
		else if (portToProtocoll(portM).compare("Unknown") != 0) //protocollo associato a portM conosciuto
		{
			arrayFlussi[i].ipM = ipD;
			arrayFlussi[i].ipD = ipM;
			arrayFlussi[i].portaM = portD;
			arrayFlussi[i].portaD = portM;
			arrayFlussi[i].protocol = protocol;
			arrayFlussi[i].lastUpdate = xt.sec; //aggiorno data ultimo update
			arrayFlussi[i].nPacchetti = 1;
		}
		else
		{
			arrayFlussi[i].ipM = ipM;
			arrayFlussi[i].ipD = ipD;
			arrayFlussi[i].portaM = portM;
			arrayFlussi[i].portaD = portD;
			arrayFlussi[i].protocol = protocol;
			arrayFlussi[i].lastUpdate = xt.sec; //aggiorno data ultimo update
			arrayFlussi[i].nPacchetti = 1;
		}
	}

	indiciAttivi.push_back(i); //aggiungo l'indice all'elenco degli indici attivi.
}

void flussi::incrementFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol)
{
	int i = hash(ipM, ipD, portM, portD, protocol);
	boost::xtime_get(&xt, boost::TIME_UTC);
	boost::mutex::scoped_lock lock(f_mutex);
	int npack = arrayFlussi[i].nPacchetti;
	lock.unlock();
	if (protocol) //Tcp
	{
		boost::mutex::scoped_lock lock(f_mutex);
		if (npack == 0 && arrayFlussi[i].portaD == 0 && arrayFlussi[i].portaM == 0) //flusso non esistente
		{
			//cout << "F - Flusso (id: " << i << ") TCP gia iniziato, scarto (" << inet_ntoa(ipM);
			//cout << " | " << inet_ntoa(ipD) << " | " << portM << " | " << portD << ")" << endl;
		}
		else
		{
			arrayFlussi[i].nPacchetti = npack + 1;
			arrayFlussi[i].lastUpdate = xt.sec;
			//cout << "F - Flusso (id: " << i << ") TCP incrementato (" << inet_ntoa(ipM);
			//cout << " | " << inet_ntoa(ipD) << " | " << portM << " | " << portD << ")" << endl;
		}
	}
	else //Udp quindi incremento, se il flusso non esiste lo aggiungo
	{
		boost::mutex::scoped_lock lock(f_mutex);
		if (npack == 0 && arrayFlussi[i].portaD == 0 && arrayFlussi[i].portaM == 0) //flusso non esistente
		{
			lock.unlock();
			addFlux(ipM, ipD, portM, portD, protocol);
			//cout << "F - Flusso (id: " << i << ") UDP aggiunto e incrementato (" << inet_ntoa(ipM);
			//cout << " | " << inet_ntoa(ipD) << " | " << portM << " | " << portD << ")" << endl;
		}
		else
		{
			arrayFlussi[i].nPacchetti = npack + 1;
			arrayFlussi[i].lastUpdate = xt.sec;
			//cout << "F - Flusso (id: " << i << ") UDP incrementato (" << inet_ntoa(ipM);
			//cout << " | " << inet_ntoa(ipD) << " | " << portM << " | " << portD << ")" << endl;
		}
	}
}

bool flussi::deleteFlux(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol)
{
	int i = hash(ipM, ipD, portM, portD, protocol);
	boost::mutex::scoped_lock lock(f_mutex);
	int npack = arrayFlussi[i].nPacchetti;
	if (npack == 0) //flusso non esistente
	{
		//cout << "F - Flusso (id: " << i << ") non esistente non posso eliminarlo" << endl;
		return false;
	}
	else
	{
		//Non cancello ogni singolo campo ma solo il numero di pacchetti.
		arrayFlussi[i].nPacchetti = 0;
		//elimino l'indice dall'elenco degli indici attivi.
		for (u_int j = 0; j < indiciAttivi.size(); j++)
		{
			if (indiciAttivi.at(j) == i) indiciAttivi.erase(indiciAttivi.begin() + j);
		}
		//cout << "F - Flusso (id: " << i << ") eliminato" << endl;
		return true;
	}
}

void flussi::setTerminato(struct in_addr ipM, struct in_addr ipD, unsigned int portM, unsigned int portD, bool protocol)
{
	int i = hash(ipM, ipD, portM, portD, protocol);
	boost::mutex::scoped_lock lock(f_mutex);
	arrayFlussi[i].terminato = true;
}

void flussi::hostPortsTcp(struct in_addr ip, vector<unsigned int> * portsTcp)
{
	(*portsTcp).clear();
	boost::mutex::scoped_lock lock(f_mutex);
	for (u_int i = 0; i < indiciAttivi.size(); i++)//ciclo solo gli indici attivi.
	{
		int indice = indiciAttivi.at(i);
		if (arrayFlussi[indice].nPacchetti != 0 && arrayFlussi[indice].ipM.s_addr == ip.s_addr && arrayFlussi[indice].protocol)
		{
			(*portsTcp).push_back(arrayFlussi[indice].portaD);
		}
	}
}

void flussi::hostPortsUdp(struct in_addr ip, vector<unsigned int> * portsUdp)
{
	(*portsUdp).clear();
	boost::mutex::scoped_lock lock(f_mutex);
	for (u_int i = 0; i < indiciAttivi.size(); i++)
	{
		int indice = indiciAttivi.at(i);
		if (arrayFlussi[indice].nPacchetti != 0 && arrayFlussi[indice].ipM.s_addr == ip.s_addr && !arrayFlussi[indice].protocol)
		{
			(*portsUdp).push_back(arrayFlussi[indice].portaD);
		}
	}
}

/*Elimina i flussi non attivi da maxSleepFlux tempo, sia tcp che udp, quelli tcp non li alimina al momento del FIN per dare modo al thread apposito di aggiornare
 *i dati degli host ricavati dai flussi
 */
void flussi::clearOldFlux()
{
	//Aggiorno la variabile temporale
	boost::xtime_get(&xt, boost::TIME_UTC);
	xt.sec = xt.sec - (maxSleepFlux * 60); //tempo attuale - maxSleepFlux minuti
	//cout << "F - elimino flussi vecchi." << endl;
	int indice;
	boost::mutex::scoped_lock lock(f_mutex);
	for (u_int i = 0; i < indiciAttivi.size(); i++)
	{
		indice = indiciAttivi.at(i);
		if (arrayFlussi[indice].nPacchetti != 0 && (arrayFlussi[indice].lastUpdate < xt.sec || arrayFlussi[indice].terminato))
		{
			string prot;
			if (arrayFlussi[indice].protocol)
				prot.assign("TCP");
			else
				prot.assign("UDP");
			arrayFlussi[indice].nPacchetti = 0;
			//elimino l'indice dall'elenco degli indici attivi.
			indiciAttivi.erase(indiciAttivi.begin() + i);
			if (false)//verbose)
			{
				cout << "F - Flusso ";
				cout << " IpM: " << inet_ntoa(arrayFlussi[indice].ipM);
				cout << " IpD: " << inet_ntoa(arrayFlussi[indice].ipD);
				cout << " portaM: " << arrayFlussi[indice].portaM;
				cout << " portaD: " << arrayFlussi[indice].portaD;
				cout << " Protocollo: " << prot;
				cout << " eliminato per Time-Out o Terminazione ( " << maxSleepFlux << "' )" << endl;
			}
		}
	}
}

void flussi::print()
{
	int indice;
	cout << "F - **************** " << indiciAttivi.size() << endl;
	for (u_int i = 0; i < indiciAttivi.size(); i++)
	{
		string prot;
		indice = indiciAttivi.at(i);
		if (arrayFlussi[indice].protocol)
			prot = prot.assign("TCP");
		else
			prot = prot.assign("UDP");
		cout << "  - Flusso:";
		cout << " IpM: " << inet_ntoa(arrayFlussi[indice].ipM);
		cout << " IpD: " << inet_ntoa(arrayFlussi[indice].ipD);
		cout << " portaM: " << arrayFlussi[indice].portaM;
		cout << " portaD: " << arrayFlussi[indice].portaD;
		cout << " Protocollo: " << prot;
		if (arrayFlussi[indice].terminato) cout << " FLUSSO TERMINATO.";
		cout << endl;
	}
	cout << "F - ****************" << endl;
}
