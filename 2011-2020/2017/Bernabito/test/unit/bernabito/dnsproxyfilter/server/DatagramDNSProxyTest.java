package unit.bernabito.dnsproxyfilter.server;

import bernabito.dnsproxyfilter.protocol.DNSQuery;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.server.DatagramDNSProxy;
import bernabito.dnsproxyfilter.util.CustomLogger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.logging.Level;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;

/**
 * Auture: Matteo Bernabito
 * Classe di unit testing per DatagramDNSProxy.
 * Mocking di tutte le dipendenze (parsing header, query, filtraggio domini)
 * Si testa solo il corretto forwarding di query e risposte.
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest(DNSQuery.class)
public class DatagramDNSProxyTest {

    private final static int PROXY_PORT = 5000;
    private final static int FAKE_DNS_SERVER_PORT = 5001;
    private DNSQuery queryMock;
    private DatagramDNSProxy datagramDNSProxy;
    private FakeDNSServer fakeDNSServer;
    private DatagramSocket clientSocket;
    private byte[] packetBuffer;
    private DatagramPacket datagramPacket;

    @Before
    public void setUp() throws Exception {
        // Mocking
        PowerMockito.mockStatic(DNSQuery.class);
        queryMock = Mockito.mock(DNSQuery.class);
        Mockito.when(DNSQuery.tryParse(any())).thenReturn(queryMock);
        // Disable logging
        CustomLogger.getLogger().setLevel(Level.OFF);
        // Setup proxy
        InetAddress[] forwardPool = {InetAddress.getLocalHost()};
        datagramDNSProxy = new DatagramDNSProxy(PROXY_PORT, null, Arrays.asList(forwardPool), 4, FAKE_DNS_SERVER_PORT);
        // Setup fake end server
        fakeDNSServer = new FakeDNSServer(FAKE_DNS_SERVER_PORT);
        // Setup fake client datagram socket
        packetBuffer = new byte[DNSProperties.UDP_MAX_LENGTH];
        clientSocket = new DatagramSocket();
        clientSocket.setSoTimeout(1000);
        datagramPacket = new DatagramPacket(packetBuffer, 0, packetBuffer.length);
        datagramPacket.setAddress(InetAddress.getLocalHost());
        datagramPacket.setPort(PROXY_PORT);
    }


    @Test(timeout = 5000)
    public void testProxyDNSForwardingAndResponse() throws Exception {
        datagramDNSProxy.start();
        fakeDNSServer.start();
        byte[] fakeQuery = {0x00, 0x01, 0x00};
        byte[] expectedResult = new byte[fakeQuery.length];
        for(int i=0; i<expectedResult.length; i++)
            expectedResult[i] = (byte) ~(fakeQuery[i]);
        datagramPacket.setData(fakeQuery);
        clientSocket.send(datagramPacket);
        datagramPacket.setData(packetBuffer);
        clientSocket.receive(datagramPacket);
        byte[] receivedData = new byte[datagramPacket.getLength()];
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(datagramPacket.getData(), datagramPacket.getOffset(), datagramPacket.getLength());
        byteArrayInputStream.read(receivedData);
        assertArrayEquals(expectedResult, receivedData);
        fakeDNSServer.join();
        assertArrayEquals(fakeQuery, fakeDNSServer.getMessageReceived());
        datagramDNSProxy.interrupt();
        datagramDNSProxy.join();
    }

    private class FakeDNSServer extends Thread {

        private DatagramSocket datagramSocket;
        private byte[] messageReceived;

        public FakeDNSServer(int port) throws Exception {
            datagramSocket = new DatagramSocket(port, null);
        }

        @Override
        public void run() {
            byte[] buffer = new byte[DNSProperties.UDP_MAX_LENGTH];
            DatagramPacket datagramPacket = new DatagramPacket(buffer, 0, buffer.length);
            try {
                datagramSocket.receive(datagramPacket);
            } catch (IOException ignored) {}
            messageReceived = new byte[datagramPacket.getLength()];
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(datagramPacket.getData(), datagramPacket.getOffset(), datagramPacket.getLength());
            try {
                byteArrayInputStream.read(messageReceived);
            } catch (IOException ignored) {}
            byte[] answer = new byte[datagramPacket.getLength()];
            for(int i=0; i<answer.length; i++)
                answer[i] = (byte) ~(messageReceived[i]);
            datagramPacket.setData(answer);
            try {
                datagramSocket.send(datagramPacket);
            } catch (IOException ignored) {}
            datagramSocket.close();
        }

        @Override
        public void interrupt() {
            super.interrupt();
            datagramSocket.close();
        }

        public byte[] getMessageReceived() {
            return messageReceived;
        }
    }

}
