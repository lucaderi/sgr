package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public abstract class CpuMetric extends ContainerMetric
{
	private double totalUsage;
	private double systemUsage;
	private int nCore;
	
	public CpuMetric(JSONObject metrics) throws InvalidAttributeValueException 
	{
		super(metrics);
	}

	@Override
	void getMetrics(JSONObject metrics) throws InvalidAttributeValueException 
	{
		JSONObject cpuStats = getCpuStats(metrics);
		
		//get system cpu usage
		Number spt = ((Number) cpuStats.get("system_cpu_usage"));
		
		if(spt != null) {
			systemUsage = spt.doubleValue();
		}else {
			throw new InvalidAttributeValueException();
		}
		
		//get cpu usage object
		JSONObject cpuUsage = (JSONObject) cpuStats.get("cpu_usage");		
		
		//get cpu usage stats
		if(cpuUsage != null)
		{
			spt = ((Number) cpuUsage.get("total_usage"));
			
			if(spt != null)
			{
				totalUsage =  spt.doubleValue();
				
				JSONArray perCpuUsage = (JSONArray) cpuUsage.get("percpu_usage");
				
				if(perCpuUsage != null)
				{
					nCore = perCpuUsage.size();
					
				}
				else {
					throw new InvalidAttributeValueException();
				}
			}
			else {
				throw new InvalidAttributeValueException();
			}
		}
		else {
			throw new InvalidAttributeValueException();
		}
	}
	
	public static double calculateCpuPercentage(CurrentCpuStats curCpuStats,PreCpuStats preCpuStats)
	{
		double cpuPercent = 0.0;
		
		double cpuDelta = curCpuStats.getTotalUsage() - preCpuStats.getTotalUsage();
		double systemDelta = curCpuStats.getSystemUsage() - preCpuStats.getSystemUsage();
		
		if(systemDelta > 0.0 && cpuDelta > 0.0)
		{
			cpuPercent = (cpuDelta / systemDelta) * curCpuStats.getnCore() * 100.0;
		}
		
		return Math.floor(cpuPercent * 100) / 100;
		
	}
	
	public double getTotalUsage() {
		return totalUsage;
	}

	public double getSystemUsage() {
		return systemUsage;
	}

	public int getnCore() {
		return nCore;
	}

	abstract JSONObject getCpuStats(JSONObject metrics)throws InvalidAttributeValueException;
}
