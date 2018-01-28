/*
 * host.cpp
 * Classe per oggetti host
 */

#include "host.hpp"

host::host() :
	so("UNKNOWN\0"), name("UNKNOWN\0"), soid(0), uptime(-1), lastboot(-1), lastseenalive(1), port80(false), ssh(false), isgateway(false),
			inactive(false), userAgent("UNKNOWN\0"), last_protocol_transp(numberOfLast), last_protocol_app(numberOfLast), last_website(numberOfLast)
{
}

host::~host() //distruttore
{
	last_protocol_transp.clear();
	last_protocol_app.clear();
	last_website.clear();
	open_ports.clear();
}

/*
 * restituisce il puntatore al mac del pacchetto
 */
u_char * host::getMac()
{
	return machost;
}

void host::setMac(u_char * mc)
{
	this->machost = mc;
}

char * host::getIphostChar() //ritorna l'ip dell'host come array di caratteri
{
	return inet_ntoa(iphost) + '\0';
}

struct in_addr host::getIp()
{
	return this->iphost;
}

void host::setIphost(struct in_addr iph)
{
	memcpy(&iphost, &iph, 4);
}

string host::getSo()
{
	return so;
}

void host::setSo(string so)
{
	this->so.assign(so);
}

string host::getHn()
{
	return name;
}

void host::setHn(string namein)
{
	//this->name = namein;
	name = name.assign(namein);
}

bool host::getPort80()
{
	return port80;
}

void host::setPort80(bool n)
{
	port80 = n;
}

bool host::getSsh()
{
	return ssh;
}

void host::setSsh(bool n)
{
	ssh = n;
}

bool host::getIsGateway()
{
	return isgateway;
}

void host::setIsGateway(bool n)
{
	isgateway = n;
}

unsigned int host::getLastseenalive()
{
	return lastseenalive;
}

void host::setLastseenalive(unsigned int lastseenalive)
{
	this->lastseenalive = lastseenalive;
}

void host::setinactive(bool n)
{
	this->inactive = n;
}

unsigned int host::getinactive()
{
	return inactive;
}

string host::getUserAgent()
{
	return userAgent;
}

void host::setUserAgent(string ua)
{
	userAgent = userAgent.assign(ua);
	//memcpy(userAgent, ua, ua.size());
}

string* host::getLastTranspProtocols() //restituisce il puntatore all'array degli ultimi protocolli del lvl applicazioni usati
{
	string * p = new string[numberOfLast];
	//boost::mutex::scoped_lock lock(last_protocol_transp_mutex);
	for (u_int i = 0; i < last_protocol_transp.size(); i++)
		p[i] = last_protocol_transp[i];
	//lock.unlock();
	return p;
}

void host::addLastTranspProtocol(string protocollo)
{
	bool trovato = false;
	//controllo se il protocollo � gi� inserito
	u_int i = 0;
	//boost::mutex::scoped_lock lock(last_protocol_transp_mutex);
	while (i < last_protocol_transp.size() && !trovato)
	{
		//cout << "  - confronto protocolli transporto: nuovo=" << protocollo << "| gia presente=" << last_protocol_transp[i] << "|" << endl;
		if (last_protocol_transp[i].compare(protocollo) == 0)
		{
			//cout << "H - protocollo lvl trasporto gia' presente." << endl;
			trovato = true;
		}
		i++;
	}
	if (!trovato) last_protocol_transp.push_back(protocollo);
	//lock.unlock();
}

/*appProt* host::getLastAppProtocols() //restituisce il puntatore all'array degli ultimi protocolli del lvl applicazioni usati
 {
 appProt * p = new appProt[numberOfLast];
 //boost::mutex::scoped_lock lock(last_protocol_app_mutex);
 for (u_int i = 0; i < last_protocol_app.size(); i++)
 p[i] = last_protocol_app[i];
 //lock.unlock();
 return p;
 }*/

void host::addLastAppProtocol(string protocollo, bool type)
{
	//controllo se il protocollo � gi� inserito
	//boost::mutex::scoped_lock lock(last_protocol_app_mutex);
	for (u_int i = 0; i < last_protocol_app.size(); i++)
	{
		//cout << "  - confronto protocolli app: nuovo=" << protocollo << "| gia presente=" << ((appProt) last_protocol_app[i]).name << "|" << endl;
		if ((((appProt) last_protocol_app[i]).name).compare(protocollo) == 0) return;
	}
	appProt nuovo;
	nuovo.name = nuovo.name.assign(protocollo);
	nuovo.type = type;
	last_protocol_app.push_back(nuovo);
	//lock.unlock();
}

string* host::getLastWebsites() //restituisce il puntatore all'array degli ultimi siti web visitati
{
	string * p = new string[numberOfLast];
	//boost::mutex::scoped_lock lock(last_website_mutex);
	for (u_int i = 0; i < last_website.size(); i++)
		p[i] = last_website[i];
	//lock.unlock();
	return p;
}

void host::addLastWebsite(string website)
{
	//controllo se il protocollo � gi� inserito
	//boost::mutex::scoped_lock lock(last_website_mutex);
	for (u_int i = 0; i < last_website.size(); i++)
	{
		if (last_website[i].compare(website) == 0)
		{
			//cout << "H - Sito web gia' presente." << endl;
			return;
		}
	}
	//cout << "H - Aggiungo sito web: " << website << endl;
	last_website.push_back(website);
	//lock.unlock();
}

vector<unsigned int>* host::getOpenPorts() //restituisce il puntatore all'array delle porte aperte
{
	/*int * p = new int[numberOfLast];
	 for (unsigned int i = 0; i < open_ports.size(); i++)
	 p[i] = open_ports[i];
	 return p;*/
	return &open_ports;
}

void host::addOpenPort(int portaaperta)
{
	open_ports.push_back(portaaperta);
}

//contrassegna gli host inattivi per pi� di maxinactiveTime
void host::markIfinactive()
{
	boost::xtime xt; //tempo
	const unsigned int maxinactiveTime = 5; //Tempo di inattivita' di un host prima di essere segnato inattivo (in minuti)

	//Aggiorno la variabile temporale
	boost::xtime_get(&xt, boost::TIME_UTC);
	xt.sec = xt.sec - (maxinactiveTime * 60); //tempo attuale - maxinactiveTime minuti
	if (this->lastseenalive < xt.sec)
	{
		inactive = true;
		//cout << "H - Host inattivo, marchio." << endl;
	}
}

void host::print()
{
	struct tm * ltime;
	char timestr[25]; //Thu Aug 23 14:55:02 2001 piu il terminatore
	cout << "----------- " << name << "-----------" << endl;
	cout << "Host : " << inet_ntoa(iphost) << endl;
	//mac:
	cout << "Mac: ";
	if (machost != 0)
	{
		/*int i = ETHER_ADDR_LEN;
		 do
		 {
		 printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *machost++);
		 } while (--i > 0);
		 */
		printf("%x:%x:%x:%x:%x:%x\n", machost[0], machost[1], machost[2], machost[3], machost[4], machost[5]);
	}
	else
		cout << "00:00:00:00:00:00" << endl;

	//converto il tempo
	time_t timeGMT = (time_t) lastseenalive;
	ltime = localtime(&timeGMT);
	strftime(timestr, sizeof timestr, "%c", ltime);
	cout << "Last seen Alive: " << timestr;// << " (" << lastseenalive << " sec.)";
	if (inactive) cout << " (Inactive)" << endl;
	cout << endl;

	if (!isgateway)
	{
		cout << "Websites: " << endl;
		for (u_int i = 0; i < last_website.size(); i++)
			cout << "  " << last_website[i] << endl;
		cout << endl;

		cout << "Transport Protocol: ";
		for (u_int i = 0; i < last_protocol_transp.size(); i++)
			cout << last_protocol_transp[i] << ", ";
		cout << endl;
		cout << endl;

		cout << "User Agent: " << userAgent << endl;
		cout << endl;

		cout << "Application Protocol: ";
		for (u_int i = 0; i < last_protocol_app.size(); i++)
		{
			string prot;
			if (last_protocol_app[i].type)
				prot = "TCP";
			else
				prot = "UDP";
			cout << last_protocol_app[i].name << " ( " << prot << " ) " << ", ";
		}
		cout << endl;
		cout << endl;
	}
	/*cout << "Open Ports: ";
	 for (u_int i = 0; i < open_ports.size(); i++)
	 cout << open_ports[i] << ", ";
	 cout << endl;*/

	if (port80) cout << "Porta 80 in uso." << endl;
	if (ssh) cout << "Porta 22 in uso." << endl;
	cout << endl;
}

bool host::printJs(string& out)
{
	struct tm * ltime;
	char timestr[25];
	//string jsonString = string(1000,' ');
	//dati: name|ip|mac|lastseenalive|inactive|WebsitesArray|UserAgent|TransportProtocolArray|ApplicationProtocolArray|
	//stringa JSON: {"name":"freevac","ip":"10.0.0.1","mac":["00","00","00","00","00","00"],"lastseenalive":"tutta la data","inactive":"0","websites":["google.com","repubblica.it"],"useragent":"blabla firefox bla","transport":["tcp","udp","icmp"],"application":["http","https"]}
	//ua: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; it; rv:1.9.2) Gecko/20100115 Firefox/3.6
	out = out.assign("{\"name\":\"");
	out = out.append(name);
	out = out.append("\",\"ip\":\"");
	string ipc = string();
	ipc.assign(getIphostChar());
	out = out.append(ipc);
	out = out.append("\",\"mac\":");
	//restituisco il mac in un array

	//se il un %x del mac ha un solo numero/lettera aggiungo uno 0 prima
	char tmpmac[3];
	char mac[50];
	sprintf(mac, "[");
	for (u_int a = 0; a < 6; a++)
	{
		sprintf(tmpmac, "%x", machost[a]);
		if (tmpmac[1] == '\0')
		{
			sprintf(tmpmac, "0%x", machost[a]);
		}
		if (a < 5) sprintf(mac, "%s\"%s\",", mac, tmpmac);
		if (a == 5) sprintf(mac, "%s\"%s\"", mac, tmpmac);
	}
	sprintf(mac, "%s]", mac);

	//sprintf(mac, "[\"%x\",\"%x\",\"%x\",\"%x\",\"%x\",\"%x\"]", machost[0], machost[1], machost[2], machost[3], machost[4], machost[5]);
	out = out.append(mac);
	out = out.append(",\"lastseenalive\":\"");
	//converto il tempo
	time_t timeGMT = (time_t) lastseenalive;
	ltime = localtime(&timeGMT);
	//strftime(timestr, sizeof timestr, "%c", ltime);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %X.000", ltime);
	out = out.append(timestr);
	out = out.append("\",\"inactive\":\"");
	if (inactive)
		out = out.append("1\",\"websites\":[");
	else
		out = out.append("0\",\"websites\":[");

	//websites
	//boost::mutex::scoped_lock lock(last_website_mutex);
	if (last_website.size() > 0) //senza , iniziale
	{
		out = out.append("\"");
		out = out.append(last_website[0]);
		out = out.append("\"");
	}
	string lw = string();
	for (u_int i = 1; i < last_website.size(); i++)
	{
		out = out.append(",\"");
		out = out.append(last_website[i]);
		out = out.append("\"");
	}
	//lock.unlock();
	out = out.append("],\"useragent\":\"");
	out = out.append(userAgent);
	out = out.append("\",\"transport\":[");

	//transport
	//boost::mutex::scoped_lock lock(last_protocol_transp_mutex);
	if (last_protocol_transp.size() > 0) //senza , iniziale
	{
		out = out.append("\"");
		out = out.append(last_protocol_transp[0]);
		out = out.append("\"");
	}
	string lpt = string();
	for (u_int j = 1; j < last_protocol_transp.size(); j++)
	{
		out = out.append(",\"");
		out = out.append(last_protocol_transp[j]);
		out = out.append("\"");
	}
	//lock.unlock();
	//application
	//boost::mutex::scoped_lock lock(last_protocol_app_mutex);
	out = out.append("],\"application\":[");
	if (last_protocol_app.size() > 0) //senza , iniziale
	{
		out = out.append("\"");
		out = out.append(last_protocol_app[0].name);
		out = out.append("(");
		if (last_protocol_app[0].type)
			out = out.append("TCP");
		else
			out = out.append("UDP");
		out = out.append(")");
		out = out.append("\"");
	}
	for (u_int z = 1; z < last_protocol_app.size(); z++)
	{
		out = out.append(",\"");
		out = out.append(last_protocol_app[z].name);
		out = out.append("(");
		if (last_protocol_app[z].type)
			out = out.append("TCP");
		else
			out = out.append("UDP");
		out = out.append(")");
		out = out.append("\"");
	}
	//lock.unlock();
	out = out.append("]}\0");
	//string * tmp = new string(jsonString);
	return true;
}
