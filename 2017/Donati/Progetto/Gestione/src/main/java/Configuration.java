import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

public class Configuration {
	public final static String CONF_PATH = "Config.txt";
	//Numero dei punti totali
	private int numberOfPoints = 100;
	//Numero di secondi tra ogni punto
	private int timeFrequency = 5;
	private ArrayList<String> listInterface = new ArrayList<String>();
	
	public Configuration() {
		try {
			BufferedReader reader = new BufferedReader ( new InputStreamReader(new FileInputStream(CONF_PATH)));
			String line = reader.readLine();
			while(line != null) {
				if(line.charAt(0) == '*')
					line=reader.readLine();
				else {
					if(line.contains("numberOfPoints")) {
						String[] tmp = line.split("=");
						this.numberOfPoints=Integer.valueOf(tmp[1]);
						line=reader.readLine();
					}
					else if(line.contains("timeFrequency")) {
						String[] tmp = line.split("=");
						this.timeFrequency=Integer.valueOf(tmp[1]);
						line=reader.readLine();
					}
					else if(line.contains("Interface")) {
						String[] tmp = line.split("=");
						//Prendo tutte le interfacce
						if(tmp[1].equals("all")) {
							Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
							for(NetworkInterface n : Collections.list(interfaces)) {
								this.listInterface.add(new String(n.getName()));
							}
						line=reader.readLine();
						}
						//Altrimenti prendo quelle richieste
						else {
							String[] tmp2 = tmp[1].split(",");
							for(int i=0;i<tmp2.length;i++)
								this.listInterface.add(tmp2[i]);
							line=reader.readLine();
						}
					}
					else {
						System.out.println("File di configurazione malformato, uso valori di default.");
						return;
					}
				}
			}
		} catch (FileNotFoundException e) {
			System.out.println("File configurarione assente! Uscita...");
			System.exit(0);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}
	
	public int getNumberOfPoints() {
		return numberOfPoints;
	}
	
	public int getTimeFrequency() {
		return timeFrequency;
	}
	
	public ArrayList<String> getList(){
		return this.listInterface;
	}

}
