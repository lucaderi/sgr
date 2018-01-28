import java.time.Instant;

import org.influxdb.annotation.Column;
import org.influxdb.annotation.Measurement;

@Measurement(name="Network")
public class Network {
	@Column(name = "time")
	private Instant time; 
	@Column(name = "cpuLoad")
	private double cpuLoad;
	@Column(name = "ping")
	private double ping;
	@Column(name = "RXpackets")
	private long RXpackets;
	@Column(name = "RXbytes")
	private long RXbytes;
	@Column(name = "RXdropped")
	private int RXdropped;
	@Column(name = "TXpackets")
	private long TXpackets;
	@Column(name = "TXbytes")
	private long TXbytes;
	@Column(name = "TXdropped")
	private int TXdropped;
	
	
	public void printInfo() {
		
		System.out.format("%-28s%-10.3f%-10.3f%-20d%-20d%-10d%-20d%-20d%-10d\n",time,cpuLoad,ping,RXpackets,RXbytes,RXdropped,TXpackets,TXbytes,TXdropped);
		
	}
	public double getPing() {
		return ping;
	}
}
