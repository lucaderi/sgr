import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;



/**
 * Rappresenta la struttura dati di un generico record dei pacchetti NetFlow5Packet.
 * @author Francesco
 */
public class NetFlow5Record
{
	 private static final long serialVersionUID = 1L;
	  /**
	   * codici per codificare i TCP FLAGS 
	   */
	  public static final byte CWR = 1; /*Congestion Window Reduced */
	  public static final byte ECE = 2; /* se settato a 1 indica che l'host supporta Explicit Congestion Notification)  */
	  public static final byte URG = 4; /* se settato a 1 indica che nel flusso sono presenti dati urgenti */
	  public static final byte ACK = 8; /*  Acknowledgment number è valido */
	  public static final byte PSH = 16; /*se settato a 1 indica che i dati in arrivo non devono essere bufferizzati ma passati subito ai livelli superiori dell'applicazione*/
	  public static final byte RST = 32; /*se settato a 1 indica che la connessione non è valida; viene utilizzato in caso di grave errore;*/
	  public static final byte SYN = 64; /*aprire una connessione TCP */
	  public static final byte FIN =(byte)128; /* e settato a 1 indica che l'host mittente del segmento vuole chiudere la connessione TCP */
	  
	  
	  private int srcaddr;    /* Source IP Address */
	  private int dstaddr;    /* Destination IP Address */
	  private int nexthop;    /* Next hop router's IP Address */
	  private short input;      /* Input interface index */
	  private short output;     /* Output interface index */
	  private int dPkts;      /* Packets sent */
	  private int dOctets;    /* Octets sent */
	  private int First;      /* SysUptime at start of flow */
	  private int Last;       /* and of last packet of the flow */
	  private short srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
	  private short dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
	  private byte pad1;        /* pad to word boundary */
	  private byte tcp_flags;   /* Cumulative OR of tcp flags */
	  private byte prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
	  private byte tos;         /* IP Type-of-Service */
	  private short src_as;     /* source peer/origin Autonomous System */
	  private short dst_as;     /* dst peer/origin Autonomous System */
	  private byte src_mask;    /* source route's mask bits */
	  private byte dst_mask;    /* destination route's mask bits */
	  private short pad2;       /* pad to word boundary */
	

	  /**
	   *  Alloca memoria per un NetFlow5Record
	   */
	  public NetFlow5Record() 
	  {
		this.nexthop = 0;
		this.input = 0;
		this.output = 0;
		this.pad1 = 0;
		this.src_as = 0;
		this.dst_as = 0;
		this.src_mask = 0;
		this.dst_mask = 0;
		this.pad2 = 0;
	}
	/**
	 * Restituisce l'indirizzo di livello rete sorgente del NetFlow5Record
	 * @return l'indirizzo di livello rete sorgente del NetFlow5Record
	 */
	public int getSrcAddr() {
		return srcaddr;
	}
	
	/**
	 * Restituisce l'indirizzo di livello rete destinazione del NetFlow5Record
	 * @return l'indirizzo di livello rete destinazione del NetFlow5Record
	 */
	public int getDstAddr() {
		return dstaddr;
	}
	/**
	 * Restiruisce il Next hop
	 * @return il Next hop
	 */
	public int getNexthop() {
		return nexthop;
	}
	/**
	 * Input interface index
	 * @return Input interface index
	 */
	public short getInput() {
		return input;
	}
	/**
	 * Output interface index
	 * @return Output interface index
	 */
	public short getOutput() {
		return output;
	}
	/**
	 * Packets sent
	 * @return Packets sent
	 */
	public int getDPkts() {
		return dPkts;
	}
	/**
	 * Octets sent
	 * @return Octets sent
	 */
	public int getDOctets() {
		return dOctets;
	}
	/**
	 * Flow Time start 
	 * @return Flow Time start UTC format
	 */
	public int getFirst() {
		return First;
	}
	/**
	 * Flow Time end 
	 * @return Flow Time end UTC format
	 */
	public int getLast() {
		return Last;
	}
	/**
	 * Restituisce la porta sorgente del NetFlow5Record nel caso in cui Upper Layer Protocol sia TCP o UDP,
	 * nel caso in cui Upper Layer Protocol sia ICMP questo campo identifica il tipo messaggio ICMP.
	 * @return la porta sorgente del NetFlow5Record
	 */
	public short getSrcPort() {
		return srcport;
	}
	/**
	 * Restituisce la porta destinazione del NetFlow5Record nel caso in cui Upper Layer Protocol sia TCP o UDP,
	 * nel caso in cui Upper Layer Protocol sia ICMP questo campo identifica il codice ICMP.
	 * @return la porta destinazione del NetFlow5Record
	 */
	public short getDstPort() {
		return dstport;
	}
	/**
	 * pad to word boundary
	 * @return pad to word boundary
	 */
	public byte getPad1() {
		return pad1;
	}

	/**
	 * Restituisce l'IP Upper layer protocol (ad esempio TCP, UDP, ICMP)
	 * @return IP Upper layer protocol
	 */
	public byte getProt() 
	{
		return prot;
	}
	/**
	 * Restituisce il ToS
	 * @return ToS
	 */
	public byte getTos() {
		return tos;
	}
	
	public short getSrc_as() {
		return src_as;
	}
	public short getDst_as() {
		return dst_as;
	}
	public byte getSrc_mask() {
		return src_mask;
	}
	public byte getDst_mask() {
		return dst_mask;
	}
	public short getPad2() {
		return pad2;
	}

	public void setSrcAddr(int srcaddr) {
		this.srcaddr = srcaddr;
	}

	public void setDstAddr(int dstaddr) {
		this.dstaddr = dstaddr;
	}

	public void setNextHop(int nexthop) {
		this.nexthop = nexthop;
	}

	public void setInput(short input) {
		this.input = input;
	}

	public void setOutput(short output) {
		this.output = output;
	}

	public void setDPkts(int pkts) {
		dPkts = pkts;
	}

	public void setDOctets(int octets) {
		dOctets = octets;
	}

	public void setFirst(int first) {
		First = first;
	}

	public void setLast(int last) {
		Last = last;
	}

	public void setSrcPort(short srcport) {
		this.srcport = srcport;
	}

	public void setDstPort(short dstport) {
		this.dstport = dstport;
	}

	public void setPad1(byte pad1) {
		this.pad1 = pad1;
	}


	public void setProt(byte prot) {
		this.prot = prot;
	}

	public void setTos(byte tos) {
		this.tos = tos;
	}

	public void setSrc_as(short src_as) {
		this.src_as = src_as;
	}

	public void setDst_as(short dst_as) {
		this.dst_as = dst_as;
	}

	public void setSrc_mask(byte src_mask) {
		this.src_mask = src_mask;
	}

	public void setDst_mask(byte dst_mask) {
		this.dst_mask = dst_mask;
	}

	public void setPad2(short pad2) {
		this.pad2 = pad2;
	}
	/**
	 * Setta a true nei tcp_flags il flag TCP flag passato per argomento
	 * @param flag
	 */
	public void setTcp_flags(byte flag)
	{
		this.tcp_flags |= flag;
	}
	/**
	 * Calcola se il flag passato per argomento è presente nei tcp_flags
	 * @param flag il flag TCP
	 * @return true se il flag passato per argomento è presente nei tcp_flags, altrimenti false
	 */
	public boolean containTcp_flags(byte flag)
	{
		if(flag == 0)return false;
		return ((this.tcp_flags & flag) == flag);
	}
	/**
	 * Calcola se i due NetFlow5Record sono eguali
	 * @return true se i due NetFlow5Record sono eguali, altrimenti false
	 */
	@Override
	public boolean equals(Object obj) {
		if(! (obj instanceof NetFlow5Record))return false;
		NetFlow5Record nfr = (NetFlow5Record)obj;
		return
		(
			this.srcaddr == nfr.srcaddr && 
			this.dstaddr == nfr.dstaddr && /* stesso IP s/d */
			this.srcport == nfr.srcport && 
			this.dstport == nfr.dstport && /* stesso porta s/d */
			this.tos == nfr.tos /* stesso ToS */
		);
	}
	/**
	 * Restituisce la chiave per questo NetFlow5Record
	 * @return la chiave per questo NetFlow5Record
	 */
	public String getKey() 
	{
		return
		(	
			""+
			this.srcaddr +
			this.dstaddr +
			this.srcport +
			this.dstport +
			this.tos
		);  
	}
	/**
	 * Aggiorna questo NetFlow5Record, con i dati newData di un altro NetFlow5Record.
	 * L'aggiornamento consiste nell'incremento del numero totole di byte, di pacchetti, 
	 * e viene settata la data di fine flusso.
	 * @param newData
	 * @return this: l'oggetto su cui è invocato questo metodo
	 */
	public NetFlow5Record update(NetFlow5Record newData)
	{
		this.dOctets += newData.dOctets;
		this.dPkts += newData.dPkts;
		this.Last = newData.Last;
		return this;
	}
	
	/**
	 * Calcola se il flusso è terminato, riguardo la condizione: il TCP flag FIN è settato a 1
	 * @return true se il flusso è terminato, altrimenti false
	 */
	public boolean hasTcpFin()
	{
		return containTcp_flags(NetFlow5Record.FIN);
	}
	/**
	 * Calcola se il flusso è terminato, rigaurdo la condizione: sono trascorsi piu' di 30minuti
	 * @return true se il flusso è terminato, altrimenti false
	 */
	public boolean isTooLong(int FLOW_TOO_LONG_SECONDS)
	{
		return(Last - First > FLOW_TOO_LONG_SECONDS);
	}
	/**
	 * Calcola se il flusso è terminato, rigaurdo la condizione: flusso inattino per piu' di 15secondi
	 * @return true se il flusso è terminato, altrimenti false
	 */
	public boolean isInactive(int FLOW_INACTIVE_SECONDS)
	{
		return( ((int)(System.currentTimeMillis()/1000)) - Last > FLOW_INACTIVE_SECONDS);
	}
	/**
	 * Scrive sullo stream di output passato per argomento il pacchetto this
	 * @param os output stream su cui scrivere 
	 * @throws IOException se si verfica un errore nell'invio dei dati
	 */
	public void write(DataOutputStream out) throws IOException
	{
		out.writeInt(srcaddr);
		out.writeInt(dstaddr);
		out.writeInt(nexthop);
		
		out.writeShort(input);
		out.writeShort(output);
		
		out.writeInt(dPkts);
		out.writeInt(dOctets);
		out.writeInt(First);
		out.writeInt(Last);
		
		out.writeShort(srcport);
		out.writeShort(dstport);
		
		out.writeByte(pad1);
		out.writeByte(tcp_flags);
		out.writeByte(prot);
		out.writeByte(tos);
		
		out.writeShort(src_as);
		out.writeShort(dst_as);
		
		out.writeByte(src_mask);
		out.writeByte(dst_mask);
		
		out.writeShort(pad2);
	}
	/**
	 * Legge dallo stream di input passato per argomento i dati, immagazzinandoli in this
	 * @param is input stream da cui leggere i dati
	 * @throws IOException se si verfica un errore nella lettura dei dati
	 */
	public void read(DataInputStream in) throws IOException
	{
		srcaddr=in.readInt();
		dstaddr=in.readInt();
		nexthop=in.readInt();
		
		input=in.readShort();
		output=in.readShort();
		
		dPkts=in.readInt();
		dOctets=in.readInt();
		First=in.readInt();
		Last=in.readInt();
		
		srcport=in.readShort();
		dstport=in.readShort();
		
		pad1=in.readByte();
		tcp_flags=in.readByte();
		prot=in.readByte();
		tos=in.readByte();
		
		src_as=in.readShort();
		dst_as=in.readShort();
		
		src_mask=in.readByte();
		dst_mask=in.readByte();
		
		pad2=in.readShort();
	}
	
}
