import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;
import org.influxdb.dto.QueryResult;
import org.influxdb.impl.InfluxDBResultMapper;

import com.sun.management.OperatingSystemMXBean;
public class Main {

	public static void main(String[] args) {
		final String dbName = "NetworkBD";
		final String rpName = "autogen";
		final String urlDB = "http://localhost:8086";
		final String root = "root";
		//Configurazione
		Configuration conf = new Configuration();
		int totalPoints = conf.getNumberOfPoints();
		int timeFrequency = conf.getTimeFrequency();
		
		//Prendo i valori iniziali
		ConfigStatAndPing startValues = new ConfigStatAndPing(conf.getList());
		
		long RXtotalPackets=startValues.getRXpackets();
		long RXtotalBytes=startValues.getRXbytes();
		int RXtotalDropped=startValues.getRXdropped();
		long TXtotalPackets=startValues.getTXpackets();
		long TXtotalBytes=startValues.getTXbytes();
		int TXtotalDropped=startValues.getTXdropped();
		
		
		
		//osBrean per leggere il valore della cpu
		OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);
		
		
		
		//Mi connetto ad influxdb e creo il database
		InfluxDB influxDB = InfluxDBFactory.connect(urlDB, root, root);
		influxDB.createDatabase(dbName);
		
		
		
		System.out.println("Sendind to DB:");
		System.out.format("%-10s%-10s%-20s%-20s%-10s%-20s%-20s%-10s\n","cpuLoad","ping","RXpackets","RXbytes","RXdropped","TXpackets","TXbytes","TXdropped");
		for(int i=0;i<totalPoints;i++) {
			long t0=System.currentTimeMillis();
			//Prendo l'utilizzo della cpu
			double cpuLoad = osBean.getSystemCpuLoad();
			//Prendo le metriche di rete
			ConfigStatAndPing stat = new ConfigStatAndPing(conf.getList());
			long diffRXpackets = stat.getRXpackets()-RXtotalPackets;
			long diffRXbytes = stat.getRXbytes()-RXtotalBytes;
			int diffRXdropped = stat.getRXdropped()-RXtotalDropped;
			
			long diffTXpackets = stat.getTXpackets()-TXtotalPackets;
			long diffTXbytes = stat.getTXbytes()-TXtotalBytes;
			int diffTXdropped = stat.getTXdropped()-TXtotalDropped;
			//Creo ed Inserisco un punto nel DB con le metriche
			Point point = Point.measurement("Network")
							.time(System.currentTimeMillis(), TimeUnit.MILLISECONDS)
							.addField("cpuLoad", cpuLoad)
							.addField("ping", stat.getPing())
							.addField("RXpackets", diffRXpackets)
							.addField("RXbytes", diffRXbytes)
							.addField("RXdropped", diffRXdropped)
							.addField("TXpackets", diffTXpackets)
							.addField("TXbytes", diffTXbytes)
							.addField("TXdropped", diffTXdropped)
							.build();
			
			influxDB.write(dbName,rpName,point);
			System.out.format("%-10.3f%-10.3f%-20d%-20d%-10d%-20d%-20d%-10d\n",cpuLoad,stat.getPing(),diffRXpackets,diffRXbytes,diffRXdropped,diffTXpackets,diffTXbytes,diffTXdropped);
			RXtotalPackets=stat.getRXpackets();
			RXtotalBytes=stat.getRXbytes();
			RXtotalDropped=stat.getRXdropped();
			TXtotalPackets=stat.getTXpackets();
			TXtotalBytes=stat.getTXbytes();
			TXtotalDropped=stat.getTXdropped();
			
			long t1=System.currentTimeMillis();
			try {
				//Levo il tempo necessario alla computazione delle metriche (circa 100 ms di media)
				Thread.sleep(timeFrequency*1000-(t1-t0));
			} catch (InterruptedException e) {
				System.out.println("Errore: Interruzione durante sleep");
				return;
			}
		}
		
		//Faccio una query per vedere il risultato dei punti mandati al DB
		Query query = new Query("SELECT * FROM Network", dbName);
		
		QueryResult result = influxDB.query(query);
		InfluxDBResultMapper resultMapper = new InfluxDBResultMapper();
		
		List<Network> resultList = resultMapper.toPOJO(result, Network.class);
		System.out.println("Query result to DB: SELECT * FROM Network");
		System.out.format("%-28s%-10s%-10s%-20s%-20s%-10s%-20s%-20s%-10s\n","time","cpuLoad","ping","RXpackets","RXbytes","RXdropped","TXpackets","TXbytes","TXdropped");
		for(Network n : resultList) {
			n.printInfo();
		}
	}

}
