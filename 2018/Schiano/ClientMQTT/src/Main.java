import java.io.File;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttMessageListener;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.MqttTopic;
import org.eclipse.paho.client.mqttv3.internal.ClientState;
import org.eclipse.paho.client.mqttv3.internal.wire.MqttInputStream;
import org.eclipse.paho.client.mqttv3.internal.wire.MqttPersistableWireMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.WebServiceClient;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import com.maxmind.geoip2.record.Postal;
import com.maxmind.geoip2.record.Subdivision;
public class Main {

	static Integer lock=0;
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			
			while (true) {
				
				Scanner s = new Scanner(new File("./Servers.txt"));
				while(s.hasNextLine()) {
					MemoryPersistence persistence = new MemoryPersistence();
					String ip =s.nextLine();
					String server = "tcp://"+ip+":1883";
					 MqttClient client = new MqttClient(server,"ciao",persistence);
					 
					 client.setCallback(new MyMqttCallback(ip,client));
					 MqttConnectOptions o = new MqttConnectOptions();
					 o.setConnectionTimeout(10);
					 try {
						 client.connect(o);

						 client.subscribe("sensor/temperature");}
					 catch(MqttException e) {};
					 Thread.sleep(1000);
					 
				}
				
				s.close();
				Thread.sleep(50000);
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MqttException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}



	
}
