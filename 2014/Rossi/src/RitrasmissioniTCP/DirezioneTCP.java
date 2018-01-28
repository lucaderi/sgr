package RitrasmissioniTCP;

import java.io.IOException;
import java.net.InetAddress;
import java.util.GregorianCalendar;

import jpcap.JpcapCaptor;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class DirezioneTCP implements Comparable {

	private InetAddress src_ip;
	private InetAddress dst_ip;
	private int src_port;
	private int dst_port;
	private long sequenzaAttesa;
	private int numeroElementi;
	private int index;
	private long[] sequenze;
	private int[] sizeSequenze;
	private int ritrasmissioni;
	private long uptime;

	public final int SIZE = 3;

	public DirezioneTCP(TCPPacket p) {
		this.src_ip = p.src_ip;
		this.dst_ip = p.dst_ip;
		this.src_port = p.src_port;
		this.dst_port = p.dst_port;
		this.ritrasmissioni = 0;
		this.numeroElementi = 0;
		this.sequenze = new long[SIZE];
		this.iniSequenze();
		this.sizeSequenze = new int[SIZE];
		this.sequenzaAttesa = p.sequence + this.getSizePacket(p);
		this.index = 0;
		this.uptime = getTime();
	}

	public long getUptime() {
		return uptime;
	}

	public void iniSequenze() {
		for (int i = 0; i < sequenze.length; i++)
			sequenze[i] = -1;
	}

	public static long getTime() {
		return new GregorianCalendar().getTimeInMillis();
	}

	public String toString() {
		return this.src_ip + " (" + this.src_port + ") -> " + this.dst_ip
				+ " (" + this.dst_port + ") Ritrasmissioni:"
				+ this.ritrasmissioni + " Ultimo aggiornamento:" + this.uptime;
	}

	private int getSizePacket(TCPPacket p) {
		if (p.syn)
			return 1;
		else
			return p.data.length;
	}

	public int getIndiceDelMinimo() {
		long min = Long.MAX_VALUE;
		int ret = 0;
		for (int i = 0; i < this.sequenze.length; i++)
			if (min < sequenze[i] && this.sequenze[i] != -1) {
				sequenze[i] = min;
				ret = i;
			}
		return ret;
	}

	public int isInSequenza(long sequenza) {

		for (int i = 0; i < sequenze.length; i++)
			if (sequenza == sequenze[i] && sequenze[i] != -1)
				return i;
		return -1;
	}

	private void recover(TCPPacket p, boolean arrivatoAckAtteso) {

		int tmpIndex;
		long tmpSequenzaAttesa;
		int size = this.getSizePacket(p);

		if (!arrivatoAckAtteso) {
			//Se non è arrivato il pacchetto con il numero di sequenza atteso.. cerchiamo il minimo nel buffer per
			//capire quale è il prossimo numero di sequenza da attendere..
			tmpSequenzaAttesa = this.sequenze[this.getIndiceDelMinimo()]
					+ this.sizeSequenze[this.getIndiceDelMinimo()];
		} else {
			//E arrivato il pacchetto con il numero di sequenza atteso..
			tmpSequenzaAttesa = this.sequenzaAttesa + size;
		}
		
		//Adesso dobbiamo verificare se il pacchetto con numero di sequenza tmpSequenzaAttesa è conservato nel
		//buffer ossia è già arrivato...
		do {

			if ((tmpIndex = this.isInSequenza(tmpSequenzaAttesa)) == -1) {
				//In questo caso non cè
				this.sequenzaAttesa = tmpSequenzaAttesa;
				
				//Eliminaniamo dal buffer tutte qui numeri di sequenza che sono minori di sequenzaAttesa
				//tanto sono inutili..
				for (int i = 0; i < this.sequenze.length; i++) {
					if (this.sequenzaAttesa > this.sequenze[i]
							&& this.sequenze[i] != -1) {
						this.sequenze[i] = -1;
						this.sizeSequenze[i] = 0;
						this.numeroElementi--;

					}
				}
				// Condizione di arresto
				break;
			} else {
				//Nel caso che tmpSequenzaAttesa sia già arrivato, calcoliamo il prossimo numero di sequenza
				//da attendere e ricominciamo da capo...
				tmpSequenzaAttesa = this.sequenze[tmpIndex]
						+ this.sizeSequenze[tmpIndex];
			}
		} while (true);
	}

	public int getFreeIndex() {
		for (int i = 0; i < sequenze.length; i++)
			if (sequenze[i] == -1)
				return i;
		return -1;
	}

	public boolean verificaRitrasmissione(TCPPacket p) {

		boolean repeat;
		this.uptime = this.getTime();
		do {
			repeat = false;
			if (p.sequence == this.sequenzaAttesa) {
				if (this.numeroElementi == 0) {
					
					this.sequenzaAttesa = p.sequence + this.getSizePacket(p);
					return false;
				} else {
					//In questo caso esiste la possibilità che il prossimo numero di sequenza da attendere
					//sia già arrivato, quindi cerchiamo di recuperarlo con il metodo recover.
					this.recover(p, true);
					return false;
				}
			} else if (p.sequence < this.sequenzaAttesa) {
				// Questa è una ritrasmissione perché é un pacchetto che abbiamo
				// già visto
				this.ritrasmissioni++;
				return true;
			} else if (p.sequence > this.sequenzaAttesa) {
				// Pacchetti nel futuro
				if (numeroElementi >= sequenze.length) {
					//In questo caso il buffer è pieno e facciamo un ripristino forzato di esso. Vedi recover
					this.recover(p, false);
					repeat = true; // Nel caso di buffer pieno dobbiamo ripetere, perché l'ultimo pacchetto arrivato
					// ha trovato il buffer pieno e ha causato l'invocazione del metodo recover liberando spazio nel
					//buffer. Se non ripetiamo: questo pacchetto verebbe scartato... 
				} else {
					//C'è ancora posto nel buffer, possiamo memorizzarci la sequenza appena arrivata
					int freeIndex = this.getFreeIndex();
					sequenze[freeIndex] = p.sequence;
					this.sizeSequenze[freeIndex] = this.getSizePacket(p);
					this.numeroElementi++;
				}

			}
		} while (repeat);
		return false;
	}

	public static long getNumberIp(InetAddress ip) {
		String s = ip.getHostAddress();
		String num = "";
		for (int i = 0; i < s.length(); i++)
			if (s.charAt(i) != '.')
				num += s.charAt(i);
		long ret = Long.parseLong(num);
		
		return ret;
	}

	public static long getKey(TCPPacket p) {
		return getNumberIp(p.src_ip) + p.src_port;
	}

	public int compareTo(Object arg0) {

		TCPPacket p = (TCPPacket) arg0;
		long p1 = this.getNumberIp(src_ip);
		long p2 = this.getNumberIp(dst_ip);
		long p1p = this.getNumberIp(p.src_ip);
		long p2p = this.getNumberIp(p.dst_ip);

		if (p1 == p1p) {
			if (p2 == p2p) {
				if (this.src_port == p.src_port)
					return this.dst_port - p.dst_port;
				return this.src_port - p.src_port;
			}
			return (int) (p2 - p2p);
		}
		return (int) (p1 - p1p);

	}

	public int getRitrasmissioni() {
		// TODO Auto-generated method stub
		return this.ritrasmissioni;
	}

	public long getSequenzaAtttesa() {
		// TODO Auto-generated method stub
		return this.sequenzaAttesa;
	}

}
