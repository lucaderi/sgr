/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 *
 * @author ricardopinto
 */
public abstract class Capturer implements Runnable {

    private String filter;
    private boolean filterActive;
    private boolean active;
    private Integer data_source;

    public Capturer(){
	this.filter = "";
	this.filterActive = false;
	this.active = true;
        this.data_source = 0;
    }

    public abstract void start();
    public abstract void stop();
    public abstract boolean isRunning();

    public void setActive(boolean active) {
	this.active = active;
    }


    public void setFilterActive(boolean filter_active) {
	this.filterActive = filter_active;
    }


    public void setFilter(String filter) {
	this.filter = filter;
    }


    public boolean isActive() {
	return active;
    }

    public Integer getDataDestination(){
        return this.data_source;
    }

    public void setDataSource( Integer n ){
        this.data_source = n;
    }

    public boolean isFilterActive() {
	return filterActive;
    }


    public String getFilter() {
	return filter;
    }

    public abstract String getCapturerName();

    protected void savePacket( Packet p ){
	if( p instanceof IPPacket )
            DataCollector.getSingleton().addPacket(this.data_source, p);
    }
}
