import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

import org.influxdb.annotation.Column;

public class ConfigStatAndPing {
	public final static String netStat = "netstat -ie";
	public final static String pingCom = "ping -c 1";
	public final static String googleIp = "8.8.8.8";
	public final static String STAT_PATH = "/sys/class/net/";
	private double ping;
	private long RXpackets=0;
	private long RXbytes=0;
	private int RXdropped=0;
	private long TXpackets=0;
	private long TXbytes=0;
	private int TXdropped=0;
	private ArrayList<String> netList;
	
	public ConfigStatAndPing(ArrayList<String> netList) {
		String line;
		this.netList=netList;
		try {
			//Leggo le metriche delle interfacce richieste
			BufferedReader configReader;
			for(String s : netList) {
				
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/rx_packets")));
				line = configReader.readLine();
				RXpackets += Long.valueOf(line);
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/rx_bytes")));
				line = configReader.readLine();
				RXbytes += Long.valueOf(line);
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/rx_dropped")));
				line = configReader.readLine();
				RXdropped += Integer.valueOf(line);
				
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/tx_packets")));
				line = configReader.readLine();
				TXpackets += Long.valueOf(line);
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/tx_bytes")));
				line = configReader.readLine();
				TXbytes += Long.valueOf(line);
				configReader = new BufferedReader ( new InputStreamReader(new FileInputStream(STAT_PATH+s+"/statistics/tx_dropped")));
				line = configReader.readLine();
				TXdropped += Integer.valueOf(line);
			}
			
			//Eseguo il ping verso 8.8.8.8 per misurare il ping
			Process pingProc = Runtime.getRuntime().exec(pingCom+" "+googleIp);
			pingProc.waitFor();
			BufferedReader pingReader = new BufferedReader ( new InputStreamReader(pingProc.getInputStream()));
			
			line = pingReader.readLine();
			
			while(line != null) {
				if(line.contains("min/avg/max")) {
					String[] tmp = line.split(" ");
					String pingString = tmp[3].split("/")[0];
					ping = Double.valueOf(pingString);
					break;
				}
				else {
					line=pingReader.readLine();
				}
			}
			
			
			
			
			
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Errore nella raccolta dati!");
			return;
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.out.println("Raccolta dati interrotta, errore.");
			return;
		}
	}
	
	public double getPing() {
		return ping;
	}
	
	public long  getRXpackets() {
		return RXpackets;
	}
	
	public long getRXbytes() {
		return RXbytes;
	}
	
	public int getRXdropped() {
		return RXdropped;
	}
	
	public long  getTXpackets() {
		return TXpackets;
	}
	
	public long getTXbytes() {
		return TXbytes;
	}
	
	public int getTXdropped() {
		return TXdropped;
	}
}
