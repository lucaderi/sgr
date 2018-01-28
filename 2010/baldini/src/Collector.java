
import java.net.*;
import java.io.*;
import java.util.*;
/**
 * Programma di Testing per testare il Processo Probe
 * @author Francesco
 *
 */
public class Collector 
{
	public static final int DEFAULT_PORT = 2121;
	/**
	 * @param args eventuale porta di ascolto
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		int port = (args.length == 1) ? Integer.parseInt(args[0]) : DEFAULT_PORT;
		DatagramSocket ds = new DatagramSocket (port);
		byte [] buffer = new byte [1500];
		DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
		
        //file di log
        PrintWriter printout = new PrintWriter(new BufferedWriter(new FileWriter("logCollector.txt")));
        
		while(true)
		{
			ds.receive(dp); // ricevo il DatagramPacket
			ByteArrayInputStream bin = new ByteArrayInputStream(dp.getData(), 0, dp.getLength());// getLength() è il numero di byte letti
			DataInputStream dis= new DataInputStream(bin);
			NetFlow5Packet p = new NetFlow5Packet();
			p.read(dis);
			NetFlow5Record rec[] = p.getRecords();
			System.out.println("*** FLUSSO ***");
			System.out.println("@ Numero di Records :"+p.getHeader().getCount());
			System.out.println("@ Numero di Sequenza:"+p.getHeader().getFlow_sequence());
			Date t = new Date((((long)p.getHeader().getSysUptime()))*1000);
			System.out.println("@ Macchina attiva da "+t.getMinutes()+" minuti e "+t.getSeconds()+" secondi");
			System.out.println("@ Data Arrivo del Flusso: " + new Date((((long)p.getHeader().getUnix_secs())*1000)));
			for(int i = 0;i < p.getNumRecord();i++)
			{
				System.out.println("RECORD "+(i+1));
				System.out.println("-> Data Iniz Flusso:"+ new Date( ((long)rec[i].getFirst())*1000) );
				System.out.println("-> Data Fine Flusso:" + new Date( ((long)rec[i].getLast())*1000 ));
				System.out.println("- ha il TCP FIN ? = "+rec[i].hasTcpFin());
				System.out.println("- Valore HASH = "+rec[i].getKey());
				System.out.println("- Byte del flusso = "+rec[i].getDOctets());
				System.out.println("- Numero di pacchetti del flusso = "+rec[i].getDPkts());
				System.out.println("+ IP Srg: "+IPv4Parser.ipToStr(rec[i].getSrcAddr()) );
				System.out.println("+ IP Dst: "+IPv4Parser.ipToStr(rec[i].getDstAddr()) );
				System.out.println("- Upper Layer Protocol:"+trasf(rec[i].getProt()));
				int ps; 
				ps = 0xFFFF & rec[i].getSrcPort() ;
				int pd; 
				pd = 0xFFFF & rec[i].getDstPort() ;
				if( trasf(rec[i].getProt()) == "ICMP" ) {
					System.out.println("# Tipo:"+ ps);
					System.out.println("# Codice:"+ pd);
				}
				else{
					System.out.println("# Porta Srg:"+ ps);
					System.out.println("# Porta Dst:"+ pd);
				}
				
			}
			System.out.println("*** FINE FLUSSO ***");
			
			//Scrittura su file
			
			printout.println("*** FLUSSO ***");
			printout.println("@ Numero di Records :"+p.getHeader().getCount());
			printout.println("@ Numero di Sequenza:"+p.getHeader().getFlow_sequence());
			t = new Date((((long)p.getHeader().getSysUptime()))*1000);
			printout.println("@ Macchina attiva da "+t.getMinutes()+" minuti e "+t.getSeconds()+" secondi");
			printout.println("@ Data Arrivo del Flusso: " + new Date((((long)p.getHeader().getUnix_secs())*1000)));
			for(int i = 0;i < p.getNumRecord();i++)
			{
				printout.println("RECORD "+(i+1));
				printout.println("-> Data Iniz Flusso:"+ new Date( ((long)rec[i].getFirst())*1000) );
				printout.println("-> Data Fine Flusso:" + new Date( ((long)rec[i].getLast())*1000 ));
				printout.println("- ha il TCP FIN ? = "+rec[i].hasTcpFin());
				printout.println("- Valore HASH = "+rec[i].getKey());
				printout.println("- Byte del flusso = "+rec[i].getDOctets());
				printout.println("- Numero di pacchetti del flusso = "+rec[i].getDPkts());
				printout.println("+ IP Srg: "+IPv4Parser.ipToStr(rec[i].getSrcAddr()) );
				printout.println("+ IP Dst: "+IPv4Parser.ipToStr(rec[i].getDstAddr()) );
				printout.println("- Upper Layer Protocol:"+trasf(rec[i].getProt()));
				int ps; 
				ps = 0xFFFF & rec[i].getSrcPort() ;
				int pd; 
				pd = 0xFFFF & rec[i].getDstPort() ;
				if( trasf(rec[i].getProt()) == "ICMP" ) {
					printout.println("# Tipo:"+ ps);
					printout.println("# Codice:"+ pd);
				}
				else{
					printout.println("# Porta Srg:"+ ps);
					printout.println("# Porta Dst:"+ pd);
				}
				
			}
			printout.println("*** FINE FLUSSO ***");
			printout.flush();
		}
		

	}
	private static String trasf(int x)
	{
		if(x == 6)return "TCP";
		if(x == 17)return "UDP";
		if(x == 1)return "ICMP";
		return "INDEFINITO";
	}

}
