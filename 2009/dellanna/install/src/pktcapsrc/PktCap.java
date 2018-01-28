/**
 * 
 */

import java.util.Scanner;

import jpcap.*;
import static jpcap.JpcapCaptor.*;


/**
 * Questa classe cattura pacchetti e mostra a video qualche informazione
 * 
 * @author dellanna
 *
 */
public class PktCap {

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		System.out.println("JAVA PACKET CAPTURE");
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
		boolean promsc= false;
		String mode="";
		System.out.print("Do you want to capture in promiscuous mode? [y,n]  ");
		if(scan.next().equals("y")){
			promsc=true;
			mode="PROMISCUOUS MODE!";
		}
		//inizia ad ascoltare sul network device scelto
		JpcapCaptor dev=openDevice(netint[i], 65536, promsc,0);
		System.out.println();
		System.out.println("Starting capture from "+netint[i].name+"...");
		System.out.println(mode);
		System.out.println();
		dev.loopPacket(-1, new PktRecImpl());
	}
}
