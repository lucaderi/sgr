package metrics;

import javax.management.InstanceNotFoundException;
import javax.naming.directory.InvalidAttributeValueException;

import org.json.simple.JSONObject;

public class NetworkMetric extends ContainerMetric
{
	private long rxBytes;
	private long txBytes;

	public NetworkMetric(JSONObject metrics) throws InvalidAttributeValueException 
	{
		super(metrics);
	}

	@Override
	void getMetrics(JSONObject metrics) throws InvalidAttributeValueException 
	{
		JSONObject interfaces = (JSONObject) metrics.get("networks");
		
		if(interfaces != null)
		{
			//get data from default interfaces eth0
			JSONObject defaultInterface = (JSONObject)interfaces.get("eth0");
			
			if(defaultInterface != null)
			{
				//get tx & rx bytes
				Number spt1 = ((Number) defaultInterface.get("rx_bytes"));
				Number spt2 = ((Number) defaultInterface.get("tx_bytes"));

				
				if(spt1 != null && spt2 != null) 
				{
					rxBytes = spt1.longValue();
					txBytes = spt2.longValue();
				}
				else {
					throw new InvalidAttributeValueException();
				}

			}
			else {
				throw new InvalidAttributeValueException();
			}
		
			//network not found
		}else {
			txBytes = -1;
			rxBytes = -1;
		}
	}

	public long getRxBytes() {
		return rxBytes;
	}

	public long getTxBytes() {
		return txBytes;
	}


}
