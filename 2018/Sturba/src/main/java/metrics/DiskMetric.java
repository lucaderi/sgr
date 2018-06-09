package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class DiskMetric extends ContainerMetric
{
	private long totalBytesIO;
	

	public DiskMetric(JSONObject metrics) throws InvalidAttributeValueException 
	{
		super(metrics);
	}

	@Override
	void getMetrics(JSONObject metrics) throws InvalidAttributeValueException 
	{
		JSONObject blkioStats = (JSONObject) metrics.get("blkio_stats");
		
		if(blkioStats != null)
		{
			JSONArray serviceBytes = (JSONArray)blkioStats.get("io_service_bytes_recursive");
			
			if(serviceBytes != null && serviceBytes.size() > 0)
			{
				JSONObject totalIO = (JSONObject)serviceBytes.get(4);
				
				Number spt = ((Number) totalIO.get("value"));
				
				if(spt != null) 
				{
					totalBytesIO = spt.longValue();
				}
				else {
					throw new InvalidAttributeValueException();
				}

			}
			//IO not found
			else {
				totalBytesIO = -1;
			}
		}
		//IO not found
		else {
			totalBytesIO = -1;
		}
	}
	
	public long getTotalBytesIO() 
	{
		return totalBytesIO;
	}

}
