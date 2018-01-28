import java.io.*;

/**
 * Classe che implementa pacchetti di tipo NetFlow5
 * Tali pacchetti sono composti da un Header Netflow5 e da un insieme di record Netflow5,
 * questi possono essere al piu' MAX_RECORD (costante definita nella classe)
 * @author Francesco
 */
public class NetFlow5Packet
{
	private static final long serialVersionUID = 1L;
	/**
	 * Numero massimo di record per ogni pacchetto
	 */
	public static final int MAX_RECORD = 30; 
	
	/**
	 * Header del pacchetto
	 */
	private NetFlow5Header header;
	/**
	 * L'insieme di record contenuti nel pacchetto
	 */
	private NetFlow5Record flows[];
	/**
	 * Il numero di record contenuti nel pacchetto
	 */
	private int numRec;
	/**
	 * Alloca memoria per un pacchetto NetFlow5
	 */
	 public NetFlow5Packet() {
		super();
		header = new NetFlow5Header();
		numRec = 0;
		flows = new NetFlow5Record[MAX_RECORD];
	}
	 /**
	  * Setta header NetFlow in this
	  * @param h l'header
	  */
	public void setHeader(NetFlow5Header h)
	{
		this.header = h;
	}
	/**
	 * Aggiunge il record NetFlow passato per argomento
	 * a questo pacchetto 
	 * @param rec il record da aggiungere al pacchetto
	 * @return true se l'inserimento ha avuto successo,
	 * false se il pacchetto è pieno e l'inserimento non ha aveuto successo.
	 */
	public boolean addRecord(NetFlow5Record rec) 
	{
		 if( numRec == MAX_RECORD )return false;
		 flows[numRec++] = rec;
		 return true;
	}
	/**
	 * Scrive sullo stream di output passato per argomento il pacchetto this
	 * @param os output stream su cui scrivere 
	 * @throws IOException se si verfica un errore nell'invio dei dati
	 */
	public void write(DataOutputStream os) throws IOException
	{
		this.header.write(os);
		for(int i=0; i<this.numRec;i++)
			this.flows[i].write(os);
	}
	/**
	 * Legge dallo stream di input passato per argomento i dati, immagazzinandoli in this
	 * @param is input stream da cui leggere i dati
	 * @throws IOException se si verfica un errore nella lettura dei dati
	 */
	public void read(DataInputStream in)throws IOException
	{
		header.read(in);
		numRec = this.header.getCount();
		flows = new NetFlow5Record[numRec];
		for(int i = 0;i < numRec;i++)
			flows[i] = new NetFlow5Record();
		for(int i = 0;i < numRec;i++)
			flows[i].read(in);
	}
	/**
	 * Restituisce l'header di questo pacchetto
	 * @return l'header del pacchetto,
	 * Il valore restituito non è una copia indipendente dell'header ma è il reference
	 * all'header contenuto nel pacchetto
	 */
	public NetFlow5Header getHeader() 
	{
		return header;
	}
	/**
	 * Restituisce l'insieme di NetFlow5Record di questo pacchetto
	 * @return l'array di NetFlow5Record contenuti nel pacchetto.
	 * Il valore restituito non è una copia indipendente dell'array ma è il reference
	 * all'array contenuto nel pacchetto
	 */
	public NetFlow5Record[] getRecords()
	{
		return flows;	
	}
	/**
	 * Restituisce il numero di NetFlow5Record di questo pacchetto
	 * @return  il numero di NetFlow5Record di questo pacchetto
	 */
	public int getNumRecord() {
		return numRec;
	}
	
}
