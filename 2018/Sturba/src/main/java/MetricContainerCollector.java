import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DecimalFormat;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import metrics.CpuMetric;
import metrics.CurrentCpuStats;
import metrics.DiskMetric;
import metrics.MemoryMetric;
import metrics.NetworkMetric;
import metrics.PreCpuStats;

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
				
				//TEST CPU
				
				//get cpu usage
				CurrentCpuStats currentCpuStats = new CurrentCpuStats(metrics);
				PreCpuStats preCpuStats = new PreCpuStats(metrics);
				
				double cpu = CpuMetric.calculateCpuPercentage(currentCpuStats, preCpuStats);
				
				//DEBUG
//				System.out.println(containerName+" cpu: "+cpu+"%");
//				Runtime.getRuntime().exec("clear");
				
				//TEST MEMORY
				
				//get memory usage
				MemoryMetric memory = new MemoryMetric(metrics);
				
				double memory_usg = MemoryMetric.calculateMemoryUsage(memory);
				
//				System.out.println(containerName+" memory: "+memory_usg+"%");
				
				//TEST NETWORK
				NetworkMetric netMetrics = new NetworkMetric(metrics);
//				
				//net stats not found
				if(netMetrics.getRxBytes() != -1 && netMetrics.getTxBytes() != -1)
				{
					double rxBytes = Math.floor( ( ((double)netMetrics.getRxBytes() / 1024.0) * 100 ) /100 );
					double txBytes = Math.floor( ( ((double)netMetrics.getTxBytes() / 1024.0) * 100 ) /100 );

//					System.out.println(containerName+ "rx: "+rxBytes + "kb tx: "+txBytes+"kb");
				}
				
				//TEST DISK
				DiskMetric diskMetric = new DiskMetric(metrics);
				
				//disk stats not found
				if(diskMetric.getTotalBytesIO() != -1)
				{
					double totalBytesIO = Math.floor( ( ((double)diskMetric.getTotalBytesIO() / 1024.0) * 100 ) /100 );
					System.out.println(containerName+"DISK IO: "+totalBytesIO+"kB");
				}
				
				//free all,for best garbage
//				currentCpuStats = null;
//				preCpuStats = null;
//				metrics = null;
//				memory = null;
//				netMetrics = null;
				
				
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
				//System.out.println(this.containerName+": "+res.get("read"));
				
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
