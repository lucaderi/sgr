/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import java.io.IOException;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

/**
 *
 * @author ricardopinto
 */
public class LiveCapturer extends Capturer {

    private NetworkInterface net_i;
    private boolean promiscuous = true;
    private boolean running = false;
    private Thread runner = null;

    public LiveCapturer( NetworkInterface ni ){
	this(ni,true);
    }

    public LiveCapturer( NetworkInterface ni, boolean prom ){
	super();
	this.net_i = ni;
	this.promiscuous = prom;
    }

    public NetworkInterface getNetworkInterface() {
	return net_i;
    }


    public void setNetworkInterface(NetworkInterface net_i) {
	this.net_i = net_i;
    }


    public boolean isPromiscuous() {
	return promiscuous;
    }


    public void setPromiscuous(boolean promiscuous) {
	this.promiscuous = promiscuous;
    }


    @Override
    public void start() {
	if( super.isActive() ){
            //System.out.println("I'm sniffing! "+this.getCapturerName());
	    this.runner = new Thread(this);
	    this.running = true;
	    this.runner.start();
	}
    }

    @Override
    public void stop() {
	this.running = false;
	this.runner = null;
    }

    private PacketReceiver handler=new PacketReceiver(){
        public void receivePacket(final Packet p) {
            savePacket(p);
	}
    };

    public void run() {
	try {
	    //65535
	    //351 is enough for IPv6 TCP packets
	    JpcapCaptor captor = JpcapCaptor.openDevice(this.net_i, 351, this.promiscuous, 20);
	    
	    //captor.setNonBlockingMode(true);

	    if (super.isFilterActive()) {
		captor.setFilter(super.getFilter(), true);
	    }

	    while (this.running) {
                //System.out.println("Saving Packet!");
                captor.processPacket(-1, handler);
		//if (captor.processPacket(-1, handler) == 0) {
		    //this.running = false;
		//}
	    }

            //System.out.println("live cap out..");

	    captor.breakLoop();
	    /*while(keep_capturing){
	    Packet a = captor.getPacket();
	    if( a!= null ) DataCollector.getSingleton().add(a);
	    }*/
	    captor.close();

	} catch (IOException ex) {
            //not the best approach, but user must be notified anyway..
            javax.swing.JOptionPane.showMessageDialog(null,
                ex.getMessage(),
                "IOException in "+this.getCapturerName(),
                javax.swing.JOptionPane.ERROR_MESSAGE);
	    //System.out.println("IOEx: "+ex.getMessage());
	}
    }

    @Override
    protected void savePacket( Packet p ){
        super.savePacket(p);
    }

    @Override
    public String getCapturerName() {
        return net_i.description+" - "+net_i.addresses+" - "+net_i.mac_address+" - "+net_i.datalink_name+" - "+net_i.datalink_description+" - "+net_i.toString();
    }

    @Override
    public boolean isRunning() {
        return running;
    }

}
