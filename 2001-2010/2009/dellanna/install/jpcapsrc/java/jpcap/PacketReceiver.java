package jpcap;

import jpcap.packet.Packet;

/** This interface is used to define a method to analyze the captured packets,
 * which is used in JpcapCaptor.handlePacket() or JpcapCaptor.processPacket()
 * @see JpcapCaptor#processPacket(int,PacketReceiver)
 * @see JpcapCaptor#loopPacket(int,PacketReceiver)
 */
public interface PacketReceiver
{
    /** Analyzes a packet.<BR>
     * <BR>
     * This method is called everytime a packet is captured.
     * @param p A packet to be analyzed
     */
  public void receivePacket(Packet p);
}
