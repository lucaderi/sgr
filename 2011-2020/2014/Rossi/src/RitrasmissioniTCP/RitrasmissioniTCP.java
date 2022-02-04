package RitrasmissioniTCP;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import javax.swing.Timer;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class RitrasmissioniTCP {
	private Hashtable table;
	private Timer allarm;
	private Object foo;

	public static final int SOGLIA_INATTIVITA_CONNESSIONE_MILLIS = 5 * 60 * 1000;
	public static final int INTERVALLO_TIME_OUT_MILLIS = 3 * 60 * 1000;

	private ActionListener allarmListener = new ActionListener() {

		public void actionPerformed(ActionEvent arg0) {
			cleanTable();
		}

	};

	public RitrasmissioniTCP(int size) {
		table = new Hashtable(size);
		foo = new LinkedList();
		allarm = new Timer(this.INTERVALLO_TIME_OUT_MILLIS, allarmListener);
		allarm.start();
		
	}

	public void removeDirezioneTCP(TCPPacket p) {
		Enumeration enum = table.elements();
		List list;
		try {
			while ((list = (List) enum.nextElement()) != null) {
				Iterator itr = list.iterator();
				while (itr.hasNext()) {
					DirezioneTCP tmp = (DirezioneTCP) itr.next();
					if (tmp.compareTo(p) == 0)
						list.remove(tmp);
				}
			}

		} catch (NoSuchElementException e) {

		}

	}

	public void cleanTable() {
		Enumeration enum = table.elements();
		List list;
		try {
			while ((list = (List) enum.nextElement()) != null) {
				Iterator itr = list.iterator();
				while (itr.hasNext()) {
					DirezioneTCP tcp = (DirezioneTCP) itr.next();
					long tempoAdesso = tcp.getTime();
					if (tempoAdesso - tcp.getUptime() > SOGLIA_INATTIVITA_CONNESSIONE_MILLIS) {
						System.out.println("\u001B[35m[TIMEOUT]\n"
								+ tcp.toString() + "\u001B[0m");
						list.remove(tcp);
					}
				}
			}
		} catch (NoSuchElementException e) {

		}

	}

	public void update(TCPPacket p) {

		List tmp;
		long keyLong = DirezioneTCP.getKey(p);
		Long key = new Long(keyLong);

		if (p.fin || p.rst) {
			// Rimozione della DirezioneTCP
			if ((tmp = (List) table.get(key)) != null) {
				Iterator itr = tmp.iterator();
				while (itr.hasNext()) {
					DirezioneTCP d = null;
					d = (DirezioneTCP) itr.next();
					if (d.compareTo(p) == 0) {
						System.out.println("\u001B[33m[CHIUSURA CONNESSIONE]\n"
								+ p + " \n\u001B[36m[Dettagli]\n "
								+ d.toString() + "\u001B[0m");
						tmp.remove(d);
					}
				}
				
			}

		} else {
			boolean rit = false;
			if ((tmp = (List) table.put(key, foo)) == null) {
				// Allora la posizione è libera, niente collisioni
				List root = new LinkedList();
				root.add(new DirezioneTCP(p));
				table.put(key, root);
				System.out.println("\u001B[34m[NEW]\n" + p + "\u001B[0m");
			} else {
				// Collisione ossia tmp != null: l'oggetto fittizio foo è
				// temporaneamente nella tabella e quindi deve essere rimosso
				Iterator itr = tmp.iterator();
				while (itr.hasNext()) {
					DirezioneTCP dir = (DirezioneTCP) itr.next();
					if (dir.compareTo(p) == 0) {
						if (dir.verificaRitrasmissione(p)) {
							System.out
									.println("\u001B[31m[RITRASMISSIONE]\n"
											+ p
											+ "\n\u001B[36m[DETTAGLI]\nSequenza Attesa "
											+ dir.getSequenzaAtttesa() + " vs "
											+ p.sequence + "\u001B[0m");
							rit = true;
						}

					}

				}
				if (!rit)
					System.out.println("\u001B[32m[OK]\n" + p + "\u001B[0m");

				table.put(key, tmp);
			}
		}
	}

	public void readRealTime(String interfaceName) {
		NetworkInterface[] interfacce = JpcapCaptor.getDeviceList();
		for (int i = 0; i < interfacce.length; i++)
			if (interfacce[i].name.equals(interfaceName)) {
				System.out.println("Inizio Cattura dalla device "
						+ interfaceName);
				try {
					JpcapCaptor pcap = JpcapCaptor.openDevice(interfacce[i],
							65535, false, 1);
					pcap.setFilter("tcp", true);
					do {
						try {

							TCPPacket tcp = (TCPPacket) pcap.getPacket();
							this.update(tcp);
						} catch (Exception e) {
						}
						;
					} while (true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
	}

	public void readFile(String fileName) throws IOException {

		JpcapCaptor pcap = JpcapCaptor.openFile(fileName);
		pcap.setFilter("tcp", true);
		int rit = 0;
		;
		do {
			Packet p = pcap.getPacket();
			if (p == null || p == Packet.EOF)
				break;
			TCPPacket tcp = (TCPPacket) p;

			try {
				if (tcp != null)
					this.update(tcp);
			} catch (Exception e) { // Per proteggersi da qualsiasi eccezione..
				System.out.println("\u001B[35m[ERRORE]\n" + e.getMessage()
						+ "\n" + tcp);
			}
		} while (true);

	}

	public static void printLogo() {
		System.out.println(" .-') _              _ (`-.  ");
		System.out.println("(  OO) )            ( (OO  ) ");
		System.out.println("/     '._  .-----. _.`     \\ ");
		System.out.println("|'--...__)'  .--./(__...--'' ");
		System.out.println("'--.  .--'|  |('-. |  /  | | ");
		System.out.println("   |  |  /_) |OO  )|  |_.' | ");
		System.out.println("   |  |  ||  |`-'| |  .___.' ");
		System.out.println("   |  | (_'  '--'\\ |  |      ");
		System.out.println("   `--'    `-----' `--'      ");
		System.out.println("       Versione 1.0");
		System.out.println("      By Rossi Matteo");
	}

	public static void main(String[] args) {
		printLogo();
		try {
			if (args.length == 0) {
				System.out
						.println("[INFO]\nParametri\n readfile <nome del file>\nrealtime <interfaccia>");
			} else {
				if (args[0].equals("realtime"))
					new RitrasmissioniTCP(200).readRealTime(args[1]);
				else if (args[0].equals("readfile")) {
					try {
						new RitrasmissioniTCP(200).readFile(args[1]);
					} catch (IOException e) {
						System.out.println("[ERRORE] " + e.getMessage());
					}
				}

			}
		} catch (Exception e) {
			System.out.println("[ERRORE] Impossibile avviare il programma...");
			System.exit(1);
		}
	}

}
