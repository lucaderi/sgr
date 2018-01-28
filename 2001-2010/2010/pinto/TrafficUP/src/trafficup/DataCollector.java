package trafficup;

import jpcap.packet.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Observable;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Write a description of class DataCollector here.
 * 
 * @author ricardopinto
 * @version 1.0
 */
public class DataCollector extends Observable
{
    private ArrayList<DataSource> dataSourceList = new ArrayList<DataSource>();
    private TreeMap<String,Flow> map_flows = new TreeMap<String,Flow>();
    private TreeSet<String> src_macs = new TreeSet<String>();
    private TreeSet<String> dst_macs = new TreeSet<String>();
    private TreeSet<Integer> src_ports = new TreeSet<Integer>();
    private TreeSet<Integer> dst_ports = new TreeSet<Integer>();
    private TreeSet<String> src_ips = new TreeSet<String>();
    private TreeSet<String> dst_ips = new TreeSet<String>();
    private TreeSet<Integer> internet_protocols = new TreeSet<Integer>();
    private TreeSet<Integer> tos = new TreeSet<Integer>();
    private TreeSet<String> net_interfaces = new TreeSet<String>();

    private long capture_start_time = 0L;
    private long capture_end_time = 0L;
    private long total_packets = 0L;
    private long total_bytes = 0L;

    private ReentrantLock flows_lock = new ReentrantLock();
    
    /**
     * Singleton mehthods
     *
     */
    private static class SingletonHolder {
	private static final DataCollector INSTANCE = new DataCollector();
    }

    private DataCollector(){}

    public static DataCollector getSingleton(){
	return SingletonHolder.INSTANCE;
    }

    public void clear(){
        flows_lock.lock();
	for( DataSource ds : this.dataSourceList ){
            ds.clear();
        }

        this.map_flows.clear();
        this.src_macs.clear();
        this.dst_macs.clear();
        this.src_ports.clear();
        this.dst_ports.clear();
        this.src_ips.clear();
        this.dst_ips.clear();
        this.internet_protocols.clear();
        this.tos.clear();
        this.net_interfaces.clear();
        this.total_bytes = this.total_packets = this.capture_start_time = this.capture_end_time = 0L;
        flows_lock.unlock();
    }

    public void setDataSources( String[] interfaces ){
        this.dataSourceList.clear();
        
        for( int i=0 ; i<interfaces.length ; i++ )
            this.dataSourceList.add(new DataSource(interfaces[i]));
    }

    /*public void triggerUpdated(){
        setChanged();
        notifyObservers();
    }*/

    public void addPacket( int index, Packet p ){
	this.dataSourceList.get(index).addPacket(p);
        this.setChanged();
    }

    /*public void addPacket( Collection<? extends Packet> l ){
        for( Packet p : l ) addPacket(p);
    }*/

    private void addFlow(Flow f){

        flows_lock.lock();

        this.src_ips.add( f.getSrc_ip() );
        this.dst_ips.add( f.getDst_ip() );
        this.internet_protocols.add( f.getProtocol() );
        this.tos.add( f.getToS() );
        this.net_interfaces.add( f.getNetI() );
        this.dst_ports.add( f.getDst_port() );
        this.src_ports.add( f.getSrc_port() );
        this.src_macs.add( f.getSrc_mac() );
        this.dst_macs.add( f.getDst_mac() );

        if( map_flows.containsKey(f.getFlowKey()) ){
            Flow tmp_f = this.map_flows.get(f.getFlowKey());
            tmp_f.addN_bytes(f.getN_bytes());
            tmp_f.addN_packets(f.getN_packets());
        }else{
            this.map_flows.put(f.getFlowKey(), f);
        }

        flows_lock.unlock();
    }

    public void parsePackets(){
        ArrayList<Packet> tmp;

        for( DataSource ds : this.dataSourceList ){

            tmp = (ArrayList<Packet>) ds.getPacketList();
            String net_i_name = ds.getNetIName();

            for( Packet p : tmp ){

                //flow variables
                String f_src_ip="";
                String f_dst_ip="";
                String f_src_mac="";
                String f_dst_mac="";
                Integer f_src_port=0;
                Integer f_dst_port=0;
                Integer f_protocol = 0;
                Integer f_tos = 0;
                long f_n_packets=0L;
                long f_n_bytes=0L;

                if( this.capture_start_time == 0L ) this.capture_start_time = p.sec;
                this.capture_end_time = p.sec;

                if( p instanceof IPPacket ){
                    f_src_ip = ((IPPacket)p).src_ip.getHostAddress();
                    f_dst_ip = ((IPPacket)p).dst_ip.getHostAddress();
                    f_protocol = (int)((IPPacket)p).protocol;
                    f_tos = (int)((IPPacket)p).rsv_tos;

                }

                if( p instanceof TCPPacket ){
                    f_src_port = ((TCPPacket)p).src_port;
                    f_dst_port = ((TCPPacket)p).dst_port;

                }

                if( p instanceof UDPPacket ){
                    f_src_port = ((UDPPacket)p).src_port;
                    f_dst_port = ((UDPPacket)p).dst_port;

                }

                if( p instanceof ICMPPacket ){
                    String type_code = "" + ((ICMPPacket)p).type + ( (((ICMPPacket)p).code < 0x0A) ? "0"+((ICMPPacket)p).code : ((ICMPPacket)p).code);
                    f_dst_port = Integer.parseInt(type_code);
                }

                EthernetPacket ep = (EthernetPacket)(p.datalink);
                f_src_mac = DataTool.byte2String(ep.src_mac);
                f_dst_mac = DataTool.byte2String(ep.dst_mac);


                f_n_packets = 1L;
                f_n_bytes = (long)p.len;

                this.total_packets += f_n_packets;
                this.total_bytes += f_n_bytes;

                Flow f = new Flow( f_src_ip, f_dst_ip, f_src_mac, f_dst_mac,
                        f_src_port, f_dst_port, f_protocol, f_tos, net_i_name, f_n_packets, f_n_bytes );

                addFlow(f);
            }
            tmp.clear();
            this.setChanged();
        }
    }

    //keep encapsulation
    public Set<String> getSrcMacs(){
	TreeSet<String> tmp = new TreeSet<String>();

	flows_lock.lock();
	for( String s : src_macs ) tmp.add(new String(s));
	flows_lock.unlock();
	
	return tmp;
    }

    //keep encapsulation
    public TreeSet<String> getDstMacs(){
	TreeSet<String> tmp = new TreeSet<String>();

	flows_lock.lock();
	for( String s : dst_macs ) tmp.add(new String(s));
	flows_lock.unlock();
	
	return tmp;
    }

    //keep encapsulation
    public TreeSet<Integer> getSrcPorts(){
	TreeSet<Integer> tmp = new TreeSet<Integer>();

	flows_lock.lock();
	for( int i : src_ports ) tmp.add(i);
	flows_lock.unlock();
	
	return tmp;
    }

    //keep encapsulation
    public TreeSet<Integer> getDstPorts(){
	TreeSet<Integer> tmp = new TreeSet<Integer>();

	flows_lock.lock();
	for( int i : dst_ports ) tmp.add(i);
	flows_lock.unlock();

	return tmp;
    }

    //keep encapsulation
    public TreeSet<String> getSrcIP(){
	TreeSet<String> tmp = new TreeSet<String>();

	flows_lock.lock();
	for( String s : src_ips ) tmp.add(new String(s));
	flows_lock.unlock();

	return tmp;
    }

    //keep encapsulation
    public TreeSet<String> getDstIP(){
	TreeSet<String> tmp = new TreeSet<String>();

	flows_lock.lock();
	for( String s : dst_ips ) tmp.add(new String(s));
	flows_lock.unlock();

	return tmp;
    }

    //keep encapsulation
    public TreeSet<Integer> getInternetProtocols(){
	TreeSet<Integer> tmp = new TreeSet<Integer>();

	flows_lock.lock();
	for( Integer s : internet_protocols ) tmp.add(s);
	flows_lock.unlock();

	return tmp;
    }

    //keep encapsulation
    public TreeSet<Integer> getToS(){
	TreeSet<Integer> tmp = new TreeSet<Integer>();

	flows_lock.lock();
	for(  int b : tos ) tmp.add(b);
	flows_lock.unlock();

	return tmp;
    }

     //keep encapsulation
    public TreeSet<String> getNetINames(){
	TreeSet<String> tmp = new TreeSet<String>();

	flows_lock.lock();
	for(  String b : net_interfaces ) tmp.add(b);
	flows_lock.unlock();

	return tmp;
    }

    public long getCaptureEnd() {
        return capture_end_time;
    }

    public long getCaptureStart() {
        return capture_start_time;
    }

    public void setCaptureEnd( long end ) {
        this.capture_end_time = end;
    }

    public void setCaptureStart( long start ) {
        this.capture_start_time = start;
    }

    public long getCaptureLength(){
        return ((capture_end_time<capture_start_time) ? (new Date()).getTime() : capture_end_time ) - capture_start_time;
    }

    public long getTotalPackets(){
        return this.total_packets;
    }

    public long getTotalBytes(){
        return this.total_bytes;
    }
    
    public Collection<Flow> getFlows(){
        Collection<Flow> tmp = new ArrayList<Flow>();

        flows_lock.lock();
        for( Flow f : map_flows.values() ) tmp.add(f);
        flows_lock.unlock();

        return tmp;
    }

    public void setFlows(Collection<Flow> flows){
        flows_lock.lock();
        map_flows.clear();
        for( Flow f : flows ) addFlow(f);
        flows_lock.unlock();
        
        this.setChanged();
    }

    private class DataSource{
        private ArrayList<Packet> packetList = new ArrayList<Packet>();
        private ReentrantLock packet_lock = new ReentrantLock();
        private String net_i_name;
        
        public DataSource( String net_i_name ){
            this.net_i_name = net_i_name;
        }

        public String getNetIName(){
            return this.net_i_name;
        }

        public void addPacket( Packet p ){
            packet_lock.lock();
            packetList.add(p);
            packet_lock.unlock();
        }

        public Collection<Packet> getPacketList(){
            ArrayList<Packet> tmp;
            packet_lock.lock();
            tmp = this.packetList;
            this.packetList = new ArrayList<Packet>();
            packet_lock.unlock();

            return tmp;
        }

        public void clear(){
            packet_lock.lock();
            this.packetList.clear();
            packet_lock.unlock();
        }
    }

}
