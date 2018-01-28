import static jpcap.JpcapCaptor.getDeviceList;
import static jpcap.JpcapCaptor.openDevice;

import java.util.Scanner;

import flow.PacketDispatcher;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;

/**
 * 
 */

/**
 * Questa classe realizza l'eseguibile del programma Packet Flow per la generazione e visualizzazione di flussi di rete basati su cattura pcap
 * 
 * @author dellanna
 *
 */
public class PktFlow {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		System.out.println("JAVA PACKET FLOW CAPTURE v1.2.0");
		System.out.println("\n\nCapture devices: \n\n");
		
		//scrive i nomi delle interfacce da cui puo' catturare pacchetti
		NetworkInterface[] netint=getDeviceList();
		byte[] m;
		NetworkInterfaceAddress[] in;
		for(int i=0;i<netint.length;i++){
			System.out.println("Device ["+i+"]");
			System.out.println("Name: "+netint[i].name);
			System.out.println("Description: "+netint[i].description);
			if(netint[i].loopback)
				System.out.println("LOOPBACK INTERFACE");
			System.out.println("Datalink name: "+netint[i].datalink_name);
			System.out.println("Datalink decription: "+netint[i].datalink_description);
			//macaddress
			m=netint[i].mac_address;
			System.out.println("MAcaddress: "+Integer.toHexString(m[0]&255).toUpperCase()+":"+Integer.toHexString(m[1]&255).toUpperCase()+":"+Integer.toHexString(m[2]&255).toUpperCase()+":"+Integer.toHexString(m[3]&255).toUpperCase()+":"+Integer.toHexString(m[4]&255).toUpperCase()+":"+Integer.toHexString(m[5]&255).toUpperCase());
			//network adresses
			in=netint[i].addresses;
			System.out.print("Network addresses: ");
			for(int j=0;j<in.length;j++)
				System.out.print(in[j].address+" ");
			System.out.println();	
			System.out.println();
		}
		System.out.println();
		System.out.print("Select device: ");
		Scanner scan =new Scanner(System.in);
		int i=scan.nextInt();
		if (i<netint.length) {
			boolean promsc = false;
			String mode = "";
			System.out
					.print("Do you want to capture in promiscuous mode? [y,n]  ");
			if (scan.next().equals("y")) {
				promsc = true;
				mode = "PROMISCUOUS MODE!";
			}
			//setta le variabili del dispatcher
			PacketDispatcher dispatcher;
			System.out.print("Do you want to load default profile? [y,n]  ");
			if (scan.next().equals("y")) {
				dispatcher = new PacketDispatcher();
			} else {
				int thash_size = 0;
				int pkt_queue_size = 0;
				int worker_size = 0;
				int flow_ttl = 0;
				int flow_inactivity = 0;
				System.out.print("Hash Table size (in K): [default=20480K]  ");
				try {
					thash_size = Integer.parseInt(scan.next());
				} catch (Exception e) {
				}
				System.out.print("Packet Queue size (in K): [default=512K]  ");
				try {
					pkt_queue_size = Integer.parseInt(scan.next());
				} catch (Exception e) {
				}
				System.out
						.print("How many worker threads do you want to load? [default=target machine cpus]  ");
				try {
					worker_size = Integer.parseInt(scan.next());
				} catch (Exception e) {
				}
				System.out
						.print("How much time do you want flows to live before expire? (in sec) [default=300sec]  ");
				try {
					flow_ttl = Integer.parseInt(scan.next());
				} catch (Exception e) {
				}
				System.out
						.print("How much time do you want flows to be inactive before expire? (in sec) [default=15sec]  ");
				try {
					flow_inactivity = Integer.parseInt(scan.next());
				} catch (Exception e) {
				}
				System.out.print("Do you want to save flows into flows.xml? (y,n) [default=y]  ");
				boolean choice=false;
				if (scan.next().equals("y")) 
					choice = true;
			
				dispatcher = new PacketDispatcher(thash_size, pkt_queue_size,
						worker_size, flow_ttl, flow_inactivity,choice);
			}
			//inizia ad ascoltare sul network device scelto: cattura al piu' 134 byte per leggere un header TCP/UDP su ip4
			JpcapCaptor dev = openDevice(netint[i], 134, promsc, 0);
			System.out.println();
			System.out.println("Starting capture from " + netint[i].name
					+ "...");
			System.out.println(mode);
			System.out.println();
			//setta la cattura non bloccante sul device scelto
			dev.setNonBlockingMode(true);
			while (true) {
				dev.processPacket(-1, dispatcher);
				Thread.yield();//il thread va in attesa attiva
			}
		}//fine if
		System.out.println("No network interface available! closing...");
	}//fine main

}
