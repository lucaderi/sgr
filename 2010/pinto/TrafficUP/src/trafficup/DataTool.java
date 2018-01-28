/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import java.util.ArrayList;
import java.util.Collection;

/**
 *
 * @author ricardopinto
 */
public class DataTool {

    private DataTool(){}

    public static byte[] string2Byte( String addr ){
        String[] hex = addr.split("(\\:|\\-)");
        byte[] true_mac = new byte[6];

        for (int i = 0; i < 6; i++) {
            true_mac[i] = (byte)Integer.parseInt(hex[i], 16);
        }

        return true_mac;
    }

    public static String byte2String(byte[] addr) {
        return byte2String(addr,':');
    }

    public static String byte2String(byte[] addr, char ch) {
            StringBuffer sb = new StringBuffer( 17 );
            for ( int i=44; i>=0; i-=4 ) {
                    int nibble =  ((int)( byte2Long(addr) >>> i )) & 0xf;
                    char nibbleChar = (char)( nibble > 9 ? nibble + ('A'-10) : nibble + '0' );
                    sb.append( nibbleChar );
                    if ( (i & 0x7) == 0 && i != 0 ) {
                            sb.append( ch );
                    }
            }
            return sb.toString();
    }

    private static long byte2Long(byte[] addr) {
        long address = 0;
            if (addr != null) {
                if (addr.length == 6) {
                    address = unsignedByteToLong(addr[5]);
                    address |= (unsignedByteToLong(addr[4]) << 8);
                    address |= (unsignedByteToLong(addr[3]) << 16);
                    address |= (unsignedByteToLong(addr[2]) << 24);
                    address |= (unsignedByteToLong(addr[1]) << 32);
                    address |= (unsignedByteToLong(addr[0]) << 40);
                }
            }
            return address;
    }

    private static long unsignedByteToLong(byte b) {
        return (long) b & 0xFF;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterDstPort( Collection<Flow> l, int prt ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getDst_port() == prt ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterSrcPort( Collection<Flow> l, int prt ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getSrc_port() == prt ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterDstIP( Collection<Flow> l, String addr ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getDst_ip().equals(addr) ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterSrcIP( Collection<Flow> l, String addr ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getSrc_ip().equals(addr) ) a.add(f);
        }

        return a;
    }


    /******************************
     *
     */
    public static Collection<Flow> filterIP( Collection<Flow> l, String addr ){
        Collection<Flow> a = new ArrayList<Flow>( filterDstIP(l,addr) );
        a.addAll( filterSrcIP(l,addr) );

        return a;
    }


    /******************************
     *
     */
    public static Collection<Flow> filterDstMAC( Collection<Flow> l, byte[] mac ){
        Collection<Flow> a = new ArrayList<Flow>();
        boolean eq;

        for( Flow f : l ){
            if( f.getDst_mac().equals(DataTool.byte2String(mac)) ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterSrcMAC( Collection<Flow> l, byte[] mac ){
        Collection<Flow> a = new ArrayList<Flow>();
        boolean eq;

        for( Flow f : l ){
            if( f.getSrc_mac().equals(DataTool.byte2String(mac)) ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterMAC( Collection<Flow> l, byte[] mac ){
        Collection<Flow> a = new ArrayList<Flow>( filterDstMAC(l,mac) );
        a.addAll( filterSrcMAC(l,mac) );

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterProtocol( Collection<Flow> l, int prot ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getProtocol() == prot ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterToS( Collection<Flow> l, int tos ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getToS() == tos ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterNetIName( Collection<Flow> l, String i_name ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getNetI().equals(i_name) ) a.add(f);
        }

        return a;
    }

    /*******************************
     *
     */
    public static Collection<Flow> filterFlowBytesMinimum( Collection<Flow> l, int x ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getN_bytes() >= x ) a.add(f);
        }

        return a;
    }

    /*******************************
     *
     */
    public static Collection<Flow> filterFlowBytesMaximum( Collection<Flow> l, int x ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getN_bytes() <= x ) a.add(f);
        }

        return a;
    }


    /*******************************
     *
     */
    public static Collection<Flow> filterFlowPacketsMinimum( Collection<Flow> l, int x ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getN_packets() >= x ) a.add(f);
        }

        return a;
    }

    /*******************************
     *
     */
    public static Collection<Flow> filterFlowPacketsMaximum( Collection<Flow> l, int x ){
        Collection<Flow> a = new ArrayList<Flow>();

        for( Flow f : l ){
            if( f.getN_packets() <= x ) a.add(f);
        }

        return a;
    }

    public static int countIP_ProtocolPackets(Collection<Flow> l, int prot) {
        Collection<Flow> tmp = DataTool.filterProtocol(l, prot);
        int total = 0;

        for( Flow f : tmp ) total += f.getN_packets();

        return total;
    }

    public static int countIP_ProtocolBytes(Collection<Flow> l, int prot) {
        Collection<Flow> tmp = DataTool.filterProtocol(l, prot);
        int total = 0;

        for( Flow f : tmp ) total += f.getN_bytes();

        return total;
    }

    public static Long getFlowN_bytes(Collection<Flow> l){
        Long x = 0L;

        for( Flow f : l ) x += f.getN_bytes();

        return x;
    }


    public static Long getFlowN_packets(Collection<Flow> l){
        Long x = 0L;

        for( Flow f : l ) x += f.getN_packets();

        return x;
    }
}
