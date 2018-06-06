import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class MetricContainerCollector implements Runnable
{	
	private String containerName;
	private String urlContainerMetricsStats;
	private JSONParser parser;

	public MetricContainerCollector(String containerName,int port) 
	{
		if(containerName == null) {
			throw new NullPointerException();
		}
		
		this.containerName = containerName;
		this.urlContainerMetricsStats = "http://localhost:"+port+"/containers/"+containerName+"/stats?stream=0";
		parser = new JSONParser();
	}

	@Override
	public void run() 
	{
		//make a get request for get metrics for this containers
		try 
		{
			JSONObject metrics = getContainerMetrics();
			
			if(metrics != null)
			{
				//TODO calculate metrics
				
				//TODO send metrics to graphite
			}
			
			
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
	}
	
	private JSONObject getContainerMetrics() throws IOException, ParseException
	{
		URL url = new URL(urlContainerMetricsStats);
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
		JSONObject res = null;
		
		try {
			res = (JSONObject)parser.parse(content.toString());
			
			if(res != null)
			{
				//DEBUG
				System.out.println(this.containerName+": "+res.get("read"));
				
				//if it is an invalid read
				if(res.get("read").equals("0001-01-01T00:00:00Z")) {
					//DEBUG
					System.out.println("LAST IS INVALID");
					return null;
				}
			}
			
			return res;
			
		} catch (Exception e) {
			//e.printStackTrace();
			return null;
		}
		finally {
			con.disconnect();
		}
	}

}
