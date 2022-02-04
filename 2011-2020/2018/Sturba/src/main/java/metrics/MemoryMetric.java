package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONObject;

public class MemoryMetric extends ContainerMetric
{
	private long usage;
	private long limit;

	public MemoryMetric(JSONObject metrics) throws InvalidAttributeValueException 
	{
		super(metrics);
	}

	@Override
	void getMetrics(JSONObject metrics) throws InvalidAttributeValueException 
	{
		JSONObject memoryStats = (JSONObject) metrics.get("memory_stats");
		
		if(memoryStats != null) 
		{
			Number spt = ((Number) memoryStats.get("usage"));
			
			if(spt != null)
			{
				usage = spt.longValue();
				
				spt = ((Number) memoryStats.get("limit"));
				
				if(spt != null)
				{
					limit = spt.longValue();
				}
				else {
					throw new InvalidAttributeValueException();
				}
			}else {
				throw new InvalidAttributeValueException();
			}
			
		}else {
			throw new InvalidAttributeValueException();
		}
	}
	
	public long getUsage() {
		return usage;
	}

	public long getLimit() {
		return limit;
	}

	public static double calculateMemoryUsage(MemoryMetric memory)
	{
		if(memory == null) {
			throw new NullPointerException();
		}
		
		double usg = 0.0;
		
		if(memory.getLimit() > 0.0)
		{
			usg = (( (double) memory.getUsage() / (double)memory.getLimit() )) * 100.0;
		}
		
		return Math.floor(usg * 100) / 100;

	}

}
