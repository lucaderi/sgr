import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Collector implements Runnable
{
	private String URL_LIST_ACTIVE_CONTAINERS;
	private int timeout = 1;
	
	private JSONParser parser;
	private int port;
	private String host;
	
	private String graphiteHost;
	private int graphitePort;
	
	private ThreadPoolExecutor threadpool;
	
	public Collector(String host,int port,String graphiteHost,int graphitePort,int timeout) 
	{
		this.port = port;
		this.host = host;
		this.graphiteHost = graphiteHost;
		this.graphitePort = graphitePort;
		this.timeout = timeout;
		
		URL_LIST_ACTIVE_CONTAINERS = "http://"+host+":"+port+"/containers/json";
	}

	@Override
	public void run() 
	{
		init();

		while(true)
		{
			try 
			{
				monitorAllActiveContainers();
				
				Thread.sleep(timeout * 1000);
			} 
			catch(Exception e) {
				e.printStackTrace();
				return;
			}
		}
		
	}
	
	private void init() 
	{
		parser = new JSONParser();
		threadpool = (ThreadPoolExecutor) Executors.newCachedThreadPool();
	}
	
	private void monitorAllActiveContainers() throws IOException, ParseException 
	{
		//make a get request to DOCKER REST API
		URL url = new URL(URL_LIST_ACTIVE_CONTAINERS);
		
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		
		con.setRequestMethod("GET");
		
		con.setRequestProperty("Content-Type", "application/json");
		
		int status = con.getResponseCode();
		
		if(status != HttpURLConnection.HTTP_OK) {
			throw new IOException("Http Connection Error");
		}
		
		//read response from stream
		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		
		String line;
		StringBuffer content = new StringBuffer();
		
		while((line = in.readLine()) != null) {
			content.append(line);
		}
		
		//parse json response
		JSONArray containers = (JSONArray)parser.parse(content.toString());
		
		if(containers.size() == 0) {
			System.out.println("No containers active");
		}
		else {
			
			Iterator<JSONObject> iterator = containers.iterator();
	        
	        while(iterator.hasNext())
	        {
	        	JSONObject container = iterator.next();
	        	
	        	JSONArray names = (JSONArray) container.get("Names");
	        	
	        	String name = (String) names.get(0);
	        	
	        	name = name.substring(1,name.length());
	        	
	        	//System.out.println(name);
	        	
	        	//a thread from the pool,collect the metric for this containers at this given time
	        	threadpool.submit(new MetricContainerCollector(name,host,port,graphiteHost,graphitePort));
	        }
		}
		
		//request terminated
		con.disconnect();
	}
	
	
	public static void main(String[] args) throws IOException 
	{
		String host = "127.0.0.1",graphiteHost = "127.0.0.1";
		int port = 4243,graphitePort = 2003,timeout = 1;
		
		//Parsing Config File
		File configFile = new File("./src/main/resources/collector.config");
		BufferedReader br = new BufferedReader(new FileReader(configFile));
		
		String line;
		while((line = br.readLine()) != null)
		{
			//is a comment
			if(line.contains("#") || line.isEmpty()) {
				continue;
			}
			else {
				String[] array = line.split("=");
				array[1] = array[1].trim();
				
				switch (array[0]) {
				case "DOCKER_REST_API_HOST":
					host = array[1];
					break;
				
				case "DOCKER_REST_API_PORT":
					port = Integer.valueOf(array[1]);
					break;
					
				case "TIMEOUT_INTERVAL_IN_SECOND":
					timeout = Integer.valueOf(array[1]);
					break;
					
				case "GRAPHITE_HOST":
					graphiteHost = array[1];
					break;
					
				case "GRAPHITE_PORT":
					graphitePort = Integer.valueOf(array[1]);
					break;
					
				default:
					break;
				}
			}
		}
		
		br.close();
		
		//System.out.println(host+" "+port+" "+timeout+" "+graphiteHost+" "+graphitePort);
				
		//starting collector
		new Collector(host,port,graphiteHost,graphitePort,timeout).run();
	}

}
