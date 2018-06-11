package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONObject;

public abstract class ContainerMetric 
{
	
	/**
	 * 
	 * @param metrics 
	 * @throws InvalidAttributeValueException if one or more required attribute were not found in the json metric
	 */
	public ContainerMetric(JSONObject metrics) throws InvalidAttributeValueException 
	{
		if(metrics == null)
			throw new NullPointerException();
		
		getMetrics(metrics);
	}
	
	abstract void getMetrics(JSONObject metrics) throws InvalidAttributeValueException;

}
