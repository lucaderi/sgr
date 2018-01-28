package integration.bernabito.dnsproxyfilter.server;

import bernabito.dnsproxyfilter.protocol.DNSHeader;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.rfc.ResponseType;
import bernabito.dnsproxyfilter.server.DatagramDNSProxy;
import bernabito.dnsproxyfilter.server.DomainFilter;
import bernabito.dnsproxyfilter.util.CustomLogger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Level;

import static org.junit.Assert.*;

/**
 * Autore: Matteo Bernabito
 * Test di integrazione per DatagramDNSProxy.
 * I test richiedono l'accesso alla rete.
 */

public class DatagramDNSProxyTest {

    private final static int PROXY_PORT = 5000;
    private DatagramDNSProxy datagramDNSProxy;

    @Before
    public void setUp() throws Exception {
        // Disable logging
        CustomLogger.getLogger().setLevel(Level.OFF);
        // Setup server
        datagramDNSProxy = new DatagramDNSProxy(PROXY_PORT, null, null, 4);
        datagramDNSProxy.start();
    }

    @Test
    public void testQueryForAValidDomainWithNoFilters() throws Exception {
        byte[] queryForGoogleIt = new byte[] {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                                             0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        Client c = new Client(queryForGoogleIt);
        DNSHeader dnsHeader = c.call();
        assertFalse(dnsHeader.isQuery());
        assertEquals(queryForGoogleIt[1], dnsHeader.getTransactionID());
        assertEquals(ResponseType.NO_ERROR, dnsHeader.getResponseType());
    }

    @Test
    public void testQueryForAValidDomainWithNoFilters10TimesSequentially() throws Exception {
        byte[] queryForGoogleIt = new byte[] {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        Client c = new Client(queryForGoogleIt);
        for(int i=0; i<10; i++) {
            queryForGoogleIt[1] = (byte) (i + 1);
            DNSHeader dnsHeader = c.setDataToSend(queryForGoogleIt).call();
            assertFalse(dnsHeader.isQuery());
            assertEquals(queryForGoogleIt[1], dnsHeader.getTransactionID());
            assertEquals(ResponseType.NO_ERROR, dnsHeader.getResponseType());
        }
    }

    @Test
    public void testQueryForAValidDomainWithNoFilter10TimesParallel() throws Exception {
        byte[] queryForGoogleIt = new byte[] {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        List<Callable<DNSHeader>> tasks = new ArrayList<>();
        for(int i=0; i<10; i++)
            tasks.add(new Client(queryForGoogleIt));
        List<Future<DNSHeader>> futures = executorService.invokeAll(tasks);
        for(Future<DNSHeader> f : futures) {
            DNSHeader dnsHeader = f.get();
            assertFalse(dnsHeader.isQuery());
            assertEquals(queryForGoogleIt[1], dnsHeader.getTransactionID());
            assertEquals(ResponseType.NO_ERROR, dnsHeader.getResponseType());
        }
    }

    @Test
    public void testQueryForANonExistantDomainWithNoFilter() throws Exception {
        byte[] queryForNonExistant = new byte[] {0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x6e, 0x6f, 0x6e,
                                                0x65, 0x78, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x06, 0x63, 0x68, 0x72, 0x6f, 0x6f, 0x72, 0x03,
                                                0x6f, 0x76, 0x68, 0x00, 0x00, 0x01, 0x00, 0x01};
        Client c = new Client(queryForNonExistant);
        DNSHeader dnsHeader = c.call();
        assertFalse(dnsHeader.isQuery());
        assertEquals(queryForNonExistant[1], dnsHeader.getTransactionID());
        assertEquals(ResponseType.NAME_ERROR, dnsHeader.getResponseType());
    }

    @Test
    public void testQueryForFilteredDomainReadFromResources() throws Exception {
        // La risorsa contiene un file con circa 3000 domini di ads
        InputStream is = getClass().getResourceAsStream("/ads_domains.txt");
        DomainFilter domainFilter = DomainFilter.loadFromStream(is);
        datagramDNSProxy.applyDomainFilter(domainFilter);
        byte[] queryForFilteredDomain = new byte[] { 0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x35, 0x31, 0x38,
                                                     0x61, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};
        Client c = new Client(queryForFilteredDomain);
        DNSHeader dnsHeader = c.call();
        assertFalse(dnsHeader.isQuery());
        assertEquals(queryForFilteredDomain[1], dnsHeader.getTransactionID());
        assertEquals(ResponseType.NAME_ERROR, dnsHeader.getResponseType());
    }


    @After
    public void tearDown() throws Exception {
        datagramDNSProxy.interrupt();
        datagramDNSProxy.join();
    }

    /**
     * Classe interna, "client DNS"
     */

    private class Client implements Callable<DNSHeader> {

        private DatagramSocket client;
        private byte[] packetBuffer;
        private DatagramPacket datagramPacket;
        private byte[] dataToSend;

        public Client(byte[] dataToSend) throws Exception {
            client = new DatagramSocket();
            client.setSoTimeout(1000);
            packetBuffer = new byte[DNSProperties.UDP_MAX_LENGTH];
            datagramPacket = new DatagramPacket(packetBuffer, 0, packetBuffer.length);
            datagramPacket.setPort(PROXY_PORT);
            datagramPacket.setAddress(InetAddress.getLocalHost());
            this.dataToSend = dataToSend;
        }

        public Client setDataToSend(byte[] dataToSend) {
            this.dataToSend = dataToSend;
            return this;
        }

        @Override
        public DNSHeader call() throws Exception {
            datagramPacket.setData(dataToSend);
            client.send(datagramPacket);
            datagramPacket.setData(packetBuffer);
            client.receive(datagramPacket);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(datagramPacket.getData(), datagramPacket.getOffset(), datagramPacket.getLength());
            DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);
            short[] header = new short[DNSProperties.HEADER_LENGTH];
            for(int i=0; i<header.length; i++)
                header[i] = dataInputStream.readShort();
            return DNSHeader.tryParse(header);
        }
    }
}
