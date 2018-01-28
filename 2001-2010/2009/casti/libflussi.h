#define NumThreadProbe 2
#define DimCoda 1000
#define DimHash (NumThreadProbe*6000)
#define DimFlussiScaduti (DimHash*2)
#define localTimeToExpire 30 //secondi per reputare un flusso scaduto dal timestamp del primo pacchetto del flusso
#define globalTimeToExpire 10 //secondi per reputare un flusso scaduto dal timestamp dell'ultimo pacchetto catturato

	pthread_mutex_t mutex[NumThreadProbe]; //array di mutex per la mutua esclusione fra main e thread operatore i-esimo
	pthread_t threadOperatori[NumThreadProbe], cleaner;
	pthread_mutex_t mutex_goCleaner;
	pthread_cond_t cond_goCleaner=PTHREAD_COND_INITIALIZER;
	short int goCleaner=0;
	short int signalTermThread[NumThreadProbe+1];
	
	
	typedef struct
	{
		unsigned long int sec;
		unsigned long int msec;
	}timestamp;
	
	timestamp lastest;
	
	
	typedef struct
	{
		timestamp ts;
		long int caplen;
		struct in_addr mittente;
		struct in_addr destinatario;
		char mitt[15];
		char dest[15];
		unsigned short int mitt_port;
		unsigned short int dest_port;
	}elemento_coda;
	
	typedef struct
	{
		int inizio;
		int fine;
		int size;
		elemento_coda coda[DimCoda];
	}coda;
	
	coda q[NumThreadProbe];	
	
	typedef struct
	{
		timestamp first_ts;
		timestamp last_ts;
		long int caplen;
		struct in_addr mittente;
		struct in_addr destinatario;
		char mitt[15];
		char dest[15];
		unsigned short int mitt_port;
		unsigned short int dest_port;
		unsigned long int byteIN;
		unsigned long int byteOUT;
		unsigned long int npackIN;
		unsigned long int npackOUT;		
		struct bucketHash *next;
	}bucketHash;
	
	bucketHash *HashTable[DimHash];
	

	typedef struct
	{
		int inizio;
		int fine;
		int size;
		bucketHash *fexp[DimFlussiScaduti];
	}flussiScaduti;
	
	flussiScaduti fsc;

int hashCoda(unsigned long int val)
{
	return(val%NumThreadProbe);
}

int hashHashTable(unsigned long int val)
{
	return(val%DimHash);
}


elemento_coda *dequeue(int num_coda)
{
	int start;
	pthread_mutex_lock(&mutex[num_coda]);
	if(q[num_coda].size>0)
	{
		q[num_coda].size--;
	 	pthread_mutex_unlock(&mutex[num_coda]);
		start=q[num_coda].inizio;
		q[num_coda].inizio=(start+1)%DimCoda;	
		return(&(q[num_coda].coda[start]));
	}
	pthread_mutex_unlock(&mutex[num_coda]);
	return(NULL);	
}

int enqueue(elemento_coda *el, int num_coda) //resituisce il numero di elementi inseriti in coda
{
	int end;
	pthread_mutex_lock(&mutex[num_coda]);
	if(q[num_coda].size<DimCoda && el!=NULL)
	{
		q[num_coda].fine=(q[num_coda].fine+1)%DimCoda;
		end=q[num_coda].fine;
		if(memcpy(&(q[num_coda].coda[end]), el, sizeof(elemento_coda))!=NULL)
		{
			q[num_coda].size++;
			pthread_mutex_unlock(&mutex[num_coda]);
			return 1;
		}
		else
			q[num_coda].fine=(end-1)%DimCoda;	
	}
	pthread_mutex_unlock(&mutex[num_coda]);
	return 0;
}

short int ts_seMaggiore(timestamp a, timestamp b)
{
	if(a.sec>b.sec)
		return(1);
	if(a.sec<b.sec)
		return(0);
	if(a.msec>b.msec)
		return(1);
	return(0);
}

short int ts_seMinore(timestamp a, timestamp b)
{
	if(a.sec<b.sec)
		return(1);
	if(a.sec>b.sec)
		return(0);
	if(a.msec<b.msec)
		return(1);
	return(0);
}

int elaboraFlusso(elemento_coda *el) //restituisce 0 in caso di fallimento
{
	bucketHash *buck;
	bucketHash *cur;
	bucketHash *prev;
	int indexHash;
	int trovato;
	int cont_buck;
	
	indexHash=hashHashTable(el->mittente.s_addr+el->destinatario.s_addr+el->dest_port+el->mitt_port);
	cur=HashTable[indexHash];
	trovato=0;
	
	if(cur==NULL)
	{
		//printf("\n\t#cur NULL\n");
		buck=(bucketHash *) malloc(sizeof(bucketHash));
		if(buck==NULL)
		{
			printf("\nThread Operatore: impossibile allocare bucket per gestire il flusso\n");
			return(0);
		}
		buck->next=NULL;
		buck->first_ts.sec=el->ts.sec;
		buck->first_ts.msec=el->ts.msec;
		buck->last_ts.sec=el->ts.sec;
		buck->last_ts.msec=el->ts.msec;
		buck->destinatario.s_addr=el->destinatario.s_addr;
		buck->mittente.s_addr=el->mittente.s_addr;
		strcpy(buck->mitt, el->mitt);
		strcpy(buck->dest, el->dest);
		buck->mitt_port=el->mitt_port;
		buck->dest_port=el->dest_port;
		//printf("\n\t# Thread Operatore: inserisco nuovo bucket in  TABHASH[%d] per %s:%d -> %s:%d\n",indexHash,buck->mitt,buck->mitt_port,buck->dest,buck->dest_port);
		buck->npackOUT=1;
		buck->byteOUT=el->caplen;
		buck->npackIN=0;
		buck->byteIN=0;
		HashTable[indexHash]=buck;
		return(1);
	}
	else
	{
		cont_buck=0;
		while(cur!=NULL && trovato==0) //scandisco la lista dei trabocchi in cerca del bucket
		{
			cont_buck++;
			/*
			printf("\n\n\t#BUCKET_CUR :: TABHASH[%d][%d]\n",indexHash,cont_buck);
			printf("\n\t#MITTENTE:= EL_CODA %s:%d | BUCKET_CUR %s:%d",el->mitt,el->mitt_port,cur->mitt,cur->mitt_port);
			printf("\n\t#DESTINATARIO:=  EL_CODA %s:%d | BUCKET_CUR %s:%d\n",el->dest,el->dest_port,cur->dest,cur->dest_port);
			*/
			if((el->mittente.s_addr==cur->mittente.s_addr)&&(el->destinatario.s_addr==cur->destinatario.s_addr) && (el->mitt_port==cur->mitt_port) && (el->dest_port==cur->dest_port)) //pacchetto OUT
			{
				//printf("\n\t#PACCHETTO OUT\n\n");
				trovato=1;
				
				//sono ordinati i timetamp?
				if(ts_seMaggiore(el->ts,cur->last_ts)) //controllo se è maggiore dell'ultimo aggiornato
				{
					cur->last_ts.sec=el->ts.sec;
					cur->last_ts.msec=el->ts.msec;
				}
				else if(ts_seMinore(el->ts,cur->first_ts)) //controllo se è minore del primo
				{
					cur->first_ts.sec=el->ts.sec;
					cur->first_ts.msec=el->ts.msec;
				}
								
				cur->npackOUT++;
				cur->byteOUT=cur->byteOUT+el->caplen;
				/*
				printf("\t NPACK OUT: %ld\n",cur->npackOUT);
				printf("\t BYTE OUT: %ld\n",cur->byteOUT);
				printf("\t NPACK IN: %ld\n",cur->npackIN);
				printf("\t BYTE IN: %ld\n",cur->byteIN);
				*/
				return(1);	

			}
			else if((el->mittente.s_addr==cur->destinatario.s_addr)&&(el->destinatario.s_addr==cur->mittente.s_addr) && (el->mitt_port==cur->dest_port) && (el->dest_port==cur->mitt_port)) //pacchetto IN
			{
				//printf("\n\t#PACCHETTO IN\n");
				trovato=1;
				
				//sono ordinati i timetamp?
				
				if(ts_seMaggiore(el->ts,cur->last_ts)) //controllo se è maggiore dell'ultimo aggiornato
				{
					cur->last_ts.sec=el->ts.sec;
					cur->last_ts.msec=el->ts.msec;
				}
				else if(ts_seMinore(el->ts,cur->first_ts)) //controllo se è minore del primo
				{
					cur->first_ts.sec=el->ts.sec;
					cur->first_ts.msec=el->ts.msec;
				}
				cur->byteIN=cur->byteIN+el->caplen;
				cur->npackIN++;
				/*
				printf("\t NPACK OUT: %ld\n",cur->npackOUT);
				printf("\t BYTE OUT: %ld\n",cur->byteOUT);
				printf("\t NPACK IN: %ld\n",cur->npackIN);
				printf("\t BYTE IN: %ld\n",cur->byteIN);
				*/
				return(1);
			}
			prev=cur;
			cur=(cur->next);
		
		}
	
		if(trovato==0)
		{
		
			buck=(bucketHash *) malloc(sizeof(bucketHash));
			if(buck==NULL)
			{
				printf("\nThread Operatore: impossibile allocare bucket per gestire il flusso\n");
				return(0);
			}
			buck->next=NULL;
			buck->first_ts.sec=el->ts.sec;
			buck->first_ts.msec=el->ts.msec;
			buck->last_ts.sec=el->ts.sec;
			buck->last_ts.msec=el->ts.msec;
			buck->destinatario.s_addr=el->destinatario.s_addr;
			buck->mittente.s_addr=el->mittente.s_addr;
			strcpy(buck->mitt, el->mitt);
			strcpy(buck->dest, el->dest);
			buck->mitt_port=el->mitt_port;
			buck->dest_port=el->dest_port;
			//printf("\n\t# Thread Operatore LISTA: inserisco nuovo bucket in TABHASH[%d] per %s:%d -> %s:%d\n",indexHash,buck->mitt,buck->mitt_port,buck->dest,buck->dest_port);
			buck->npackOUT=1;
			buck->byteOUT=el->caplen;
			buck->npackIN=0;
			buck->byteIN=0;
			prev->next=(struct bucketHash *) buck;
			return(1);
		}
	}
}

int rimuoviScaduti()
{
	int start;

	for(start=fsc.inizio; start<fsc.inizio+fsc.size; start=(start+1)%DimFlussiScaduti)
	{
		printf("\n\nFLUSSO SCADUTO:\n");
		printf("\n\tDA %s:%d A %s:%d\n",(fsc.fexp[start])->mitt,(fsc.fexp[start])->mitt_port,(fsc.fexp[start])->dest,(fsc.fexp[start])->dest_port);
		printf("\n\tPACCHETTI SCAMBIATI: %ld | IN: %ld | OUT: %ld\n",(fsc.fexp[start])->npackIN+(fsc.fexp[start])->npackOUT, (fsc.fexp[start])->npackIN, (fsc.fexp[start])->npackOUT);
		printf("\n\tBYTE SCAMBIATI: %ld | IN: %ld | OUT: %ld\n",(fsc.fexp[start])->byteIN + (fsc.fexp[start])->byteOUT, (fsc.fexp[start])->byteIN, (fsc.fexp[start])->byteOUT);
		printf("\n\tFIRST TS: %ld.%ld | LAST TS: %ld.%ld | LASTEST TS: %ld.%ld\n",(fsc.fexp[start])->first_ts.sec,(fsc.fexp[start])->first_ts.msec,(fsc.fexp[start])->last_ts.sec,(fsc.fexp[start])->last_ts.sec,lastest.sec,lastest.msec);
		free(fsc.fexp[start]);
	}
	
	fsc.inizio=0;
	fsc.size=0;
	fsc.fine=-1;
}

int inserisciScaduto(bucketHash *el)
{
	int end;
	
	if(fsc.size<DimFlussiScaduti)
	{
		fsc.fine=(fsc.fine+1)%DimFlussiScaduti;	
		end=fsc.fine;
		if (el!=NULL)
		{
			
			fsc.fexp[end]=el;
			//printf("\n\t#mittente: %s:%d\n",fsc.fexp[end]->mitt,fsc.fexp[end]->mitt_port);
			//printf("\n\t#destinatario: %s:%d\n",fsc.fexp[end]->dest,fsc.fexp[end]->dest_port);
			fsc.size++;
			
			return(1);
		}
		else
			fsc.fine=(fsc.fine-1)%DimFlussiScaduti;	
	}
	return(0);
}

void liberaHash()
{
	int j;
	int cont; 
	bucketHash *tmp;

	for(j=0;j<DimHash;j++)
	{
		//printf("\nCONTROLLO HashTable[%d]\n",j);
		cont=0;
		while(HashTable[j]!=NULL)
		{
			tmp=HashTable[j]->next;
			//printf("\n\tHashTable[%d][%d]: ",j,cont);
			//printf("%s -> %s\n",HashTable[j]->mitt,HashTable[j]->dest);
			free(HashTable[j]);
			//printf("\n\tliberato %ld\n",HashTable[j]);
			HashTable[j]=tmp;
			//printf("\n\tHashTable[%d]: %ld\n",j,HashTable[j]);
		}
	}
}
