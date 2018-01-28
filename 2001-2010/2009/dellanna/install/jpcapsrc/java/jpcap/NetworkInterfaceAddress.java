package jpcap;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This class represents a network address assigned to a network interface.
 * @author kfujii
 */
public class NetworkInterfaceAddress{
	/** Address of the network interface */
	public InetAddress address;
	/** Subnet mask of the network interface */
	public InetAddress subnet;
	/** Broadcast address of the network interface. May be null. */
	public InetAddress broadcast;
	/** Destination address of the network interface (for P2P connection). May be null. */
	public InetAddress destination;
	
	public NetworkInterfaceAddress(byte[] address,byte[] subnet,byte[] broadcast,byte[] destination){
		try{
			if(address!=null)
				this.address=InetAddress.getByAddress(address);
			if(subnet!=null)
				this.subnet=InetAddress.getByAddress(subnet);
			if(broadcast!=null)
				this.broadcast=InetAddress.getByAddress(broadcast);
			if(destination!=null)
				this.destination=InetAddress.getByAddress(destination);
		}catch(UnknownHostException e){
		}
	}
}