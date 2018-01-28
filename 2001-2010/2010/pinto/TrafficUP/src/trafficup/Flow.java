/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import java.io.Serializable;

/**
 *
 * @author Ricardo
 */
public class Flow implements Serializable {

    private String src_ip;
    private String dst_ip;
    private String src_mac;
    private String dst_mac;
    private int src_port;
    private int dst_port;
    private int protocol;
    private int tos;
    private String net_i;
    private long n_packets;
    private long n_bytes;

    public Flow(String src_ip, String dst_ip, String src_mac, String dst_mac,
            int src_port, int dst_port, int protocol, int tos, String net_i) {
        this(src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, protocol, tos, net_i, 0L, 0L);
    }

    public Flow(String src_ip, String dst_ip, String src_mac, String dst_mac,
            int src_port, int dst_port, int protocol, int tos, String net_i,
            long n_packets, long n_bytes) {
        this.src_ip = src_ip;
        this.dst_ip = dst_ip;
        this.src_mac = src_mac;
        this.dst_mac = dst_mac;
        this.src_port = src_port;
        this.dst_port = dst_port;
        this.protocol = protocol;
        this.tos = tos;
        this.net_i = net_i;
        this.n_packets = n_packets;
        this.n_bytes = n_bytes;
    }

    private Flow(Flow f) {
        this(f.getSrc_ip(), f.getDst_ip(), f.getSrc_mac(), f.getDst_mac(),
                f.getSrc_port(), f.getDst_port(), f.getProtocol(),
                f.getToS(), f.getNetI(), f.getN_packets(), f.getN_bytes());
    }

    public String getDst_ip() {
        return dst_ip;
    }

    public String getDst_mac() {
        return dst_mac;
    }

    public int getDst_port() {
        return dst_port;
    }

    public long getN_bytes() {
        return n_bytes;
    }

    public long getN_packets() {
        return n_packets;
    }

    public String getSrc_ip() {
        return src_ip;
    }

    public String getSrc_mac() {
        return src_mac;
    }

    public int getSrc_port() {
        return src_port;
    }

    public int getProtocol() {
        return protocol;
    }

    public int getToS(){
        return tos;
    }

    public String getNetI() {
        return net_i;
    }


    public void addN_bytes(long n_bytes) {
        this.n_bytes += n_bytes;
    }

    public void addN_packets(long n_packets) {
        this.n_packets += n_packets;
    }

    public String getFlowKey(){
        return this.src_ip+this.src_port+this.dst_ip+this.dst_port+this.src_mac
                +this.dst_mac+this.protocol+this.tos+this.net_i;
    }

    @Override
    public String toString(){
        StringBuilder a = new StringBuilder("Flow:\n");
        a.append("Src_IP:Src_Port: "+this.src_ip+":"+this.src_port+"\n");
        a.append("Dst_IP:"+this.dst_ip+":"+this.dst_port+"\n");
        a.append("Src_Mac:"+this.src_mac+"\n");
        a.append("Dst_Mac:"+this.dst_mac+"\n");
        a.append("Protocol:"+this.protocol+"\n");
        a.append("ToS:"+this.tos+"\n");
        a.append("Network Interface: "+this.net_i+"\n");
        a.append("#Packets:"+this.n_packets+"\n");
        a.append("#Bytes:"+this.n_bytes+"\n");
        return  a.toString();
    }

    /*@Override
    public Flow clone(){
        return new Flow(this);
    }*/
}
