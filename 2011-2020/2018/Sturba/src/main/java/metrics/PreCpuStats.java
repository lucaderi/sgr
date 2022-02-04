package metrics;

import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONObject;

public class PreCpuStats extends CpuMetric{

	public PreCpuStats(JSONObject metrics) throws InvalidAttributeValueException {
		super(metrics);
	}

	@Override
	JSONObject getCpuStats(JSONObject metrics) throws InvalidAttributeValueException {
		return (JSONObject) metrics.get("precpu_stats");
	}

}
