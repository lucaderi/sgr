import java.io.File;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Pong;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import com.maxmind.geoip2.record.Postal;
import com.maxmind.geoip2.record.Subdivision;

public class MyMqttCallback implements MqttCallback {
	private String ip;
	static String cityDatabase = "GeoLite2-City.mmdb";
	static String countryDatabase = "GeoLite2-Country.mmdb";
	private MqttClient client ;
	public MyMqttCallback(String ip,MqttClient client) {
		this.ip=ip;
		this.client=client;
	}

	@Override
	public void connectionLost(Throwable arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void deliveryComplete(IMqttDeliveryToken arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void messageArrived(String arg0, MqttMessage arg1) throws Exception {
		synchronized(Main.lock) {
			File dbFile = new File(cityDatabase);
	     DatabaseReader reader = new DatabaseReader.Builder(dbFile).build();
	     InetAddress ipAddress = InetAddress.getByName(ip);
	       CityResponse response = reader.city(ipAddress);
	       Country country = response.getCountry();
	       System.out.println("Country Name: "+ country.getName()); 
	       System.out.println(ip);
	       Subdivision subdivision = response.getMostSpecificSubdivision();
	       City city = response.getCity();
	       System.out.println("City Name: "+ city.getName()); 
	       Postal postal = response.getPostal();
	       System.out.println("Codice Postale: "+postal.getCode()); 
		System.out.println("Temperatura "+arg1);
		InfluxDB influxDB = InfluxDBFactory.connect("http://localhost:8086");
		System.out.println(influxDB.databaseExists("Temperature"));
		if(!influxDB.databaseExists("Temperature"))
			influxDB.createDatabase("Temperature");
		Point point = Point.measurement(city.getName())
				.addField("stato", country.getName())
				.addField("codice postale", postal.getCode())
				.addField("temperatura",Double.parseDouble(arg1.toString()))
				.time(System.currentTimeMillis(), TimeUnit.MILLISECONDS).
				build();
		influxDB.setDatabase("Temperature");
		influxDB.write(point);
		this.client.disconnect();
		this.client.close();
			
		}
		
		
		
	}

}
