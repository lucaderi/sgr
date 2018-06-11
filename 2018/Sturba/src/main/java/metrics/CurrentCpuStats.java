package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONObject;

public class CurrentCpuStats extends CpuMetric{

	public CurrentCpuStats(JSONObject metrics) throws InvalidAttributeValueException {
		super(metrics);
	}

	@Override
	JSONObject getCpuStats(JSONObject metrics) 
	{
		return (JSONObject) metrics.get("cpu_stats");
	}


}
