import java.io.BufferedReader;
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


//TODO insert a dinamic port for REST API,insert into a config file
//TODO insert dinamic timeout, into config file

public class Collector implements Runnable
{
	private String URL_LIST_ACTIVE_CONTAINERS;
	private static final  int timeout = 1000;
	
	private JSONParser parser;
	private int port;
	private ThreadPoolExecutor threadpool;
	
	public Collector(int port) 
	{
		this.port = port;
		URL_LIST_ACTIVE_CONTAINERS = "http://localhost:"+port+"/containers/json";
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
				
				Thread.sleep(timeout);
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
	        	threadpool.submit(new MetricContainerCollector(name,port));
	        }
		}
		
		//request terminated
		con.disconnect();
	}
	
	
	public static void main(String[] args) 
	{
		//TODO parsing argument
		
		//starting collector
		new Collector(4243).run();
	}

}
