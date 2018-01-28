import java.io.IOException;

import java.io.*;


/**
 * Rappresenta la struttura dati dell'header del pacchetto NetFlow5Packet.
 * @author Francesco
 */
public class NetFlow5Header
{
	
	private static final long serialVersionUID = 1L;
	
	private short version; /* Current version=5*/
	private short count; /* The number of records in PDU. */
	private int sysUptime; /* Current time in msecs since router booted */
	private int unix_secs; /* Current seconds since 0000 UTC 1970 */
	private int unix_nsecs; /* Residual nanoseconds since 0000 UTC 1970 */
	private int flow_sequence; /* Sequence number of total flows seen */
	private byte engine_type; /* Type of flow switching engine (RP,VIP,etc.)*/
	private byte engine_id; /* Slot number of the flow switching engine */
	
	public NetFlow5Header(){
		super();
	}
	/**
	 * Alloca memoria per un NetFlow5Header
	 * @param count il NetFlow5Record contenuti nel PDU del NetFlow5Packet.
	 * @param sysUptime Tempo in msecondi da quando il processo si è attivato
	 * @param unix_secs Tempo in millisecondi dal 0000 UTC 1970
	 * @param flow_sequence Numero di sequenza di flussi visti
	 */
	public NetFlow5Header
	(short count, int sysUptime,int unix_secs, int flow_sequence) 
	{
		super();
		this.version = 5;
		this.count = count;
		this.sysUptime = sysUptime;
		this.unix_secs = unix_secs;
		this.unix_nsecs = 0;
		this.flow_sequence = flow_sequence;
		this.engine_type = 0;
		this.engine_id = 0;
	}
	/**
	 *  Current version=5
	 */
	public short getVersion() {
		return version;
	}
	/** 
	 * The number of records in PDU. 
	 * @return The number of records in PDU
	 */
	public short getCount() {
		return count;
	}
	/** 
	 * Current time in msecs since process booted 
	 * @return Current time in msecs since process booted 
	 */
	public int getSysUptime() {
		return sysUptime;
	}
	/** Current seconds since 0000 UTC 1970 
	 * @return Current seconds since 0000 UTC 1970 
	 */
	public int getUnix_secs() {
		return unix_secs;
	}
	/** 
	 * Residual nanoseconds since 0000 UTC 1970
	 * @return nanoseconds since 0000 UTC 1970
	 */
	public int getUnix_nsecs() {
		return unix_nsecs;
	}
	/** 
	 * Sequence number of total flows seen 
	 * @return  Sequence number of total flows seen 
	 */
	public int getFlow_sequence() {
		return flow_sequence;
	}
	/**
	 * Type of flow switching engine (RP,VIP,etc.)
	 * @return Type of flow switching engine (RP,VIP,etc.)
	 */
	public byte getEngine_type() {
		return engine_type;
	}
	/**
	 * Slot number of the flow switching engine
	 * @return Slot number of the flow switching engine
	 */
	public byte getEngine_id() {
		return engine_id;
	}
	/**
	 * Scrive sullo stream di output passato per argomento il pacchetto this
	 * @param os output stream su cui scrivere 
	 * @throws IOException se si verfica un errore nell'invio dei dati
	 */
	public void write(DataOutputStream out) throws IOException
	{
		out.writeShort(version);
		out.writeShort(count);
		out.writeInt(sysUptime);
		out.writeInt(unix_secs);
		out.writeInt(unix_nsecs);
		out.writeInt(sysUptime);
		out.writeByte(engine_type);
		out.writeByte(engine_id);
	}
	/**
	 * Legge dallo stream di input passato per argomento i dati, immagazzinandoli in this
	 * @param is input stream da cui leggere i dati
	 * @throws IOException se si verfica un errore nella lettura dei dati
	 */
	public void read(DataInputStream in) throws IOException
	{
		version = in.readShort();
		count = in.readShort();
		sysUptime= in.readInt();
		unix_secs = in.readInt();
		unix_nsecs = in.readInt();
		sysUptime = in.readInt();
		engine_type = in.readByte();
		engine_id = in.readByte();
	}
	
}
