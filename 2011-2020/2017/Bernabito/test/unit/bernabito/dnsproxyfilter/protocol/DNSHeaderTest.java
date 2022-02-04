package unit.bernabito.dnsproxyfilter.protocol;

import bernabito.dnsproxyfilter.protocol.DNSHeader;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSHeaderException;
import bernabito.dnsproxyfilter.rfc.OperationType;
import bernabito.dnsproxyfilter.rfc.ResponseType;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Autore: Matteo Bernabito
 * Classe di unit testing per DNSHeader.
 */

public class DNSHeaderTest {

    @Test(expected = MalformedDNSHeaderException.class)
    public void testParseWithInvalidHeaderLength() throws Exception {
        DNSHeader.tryParse(new short[5]);
    }

    @Test(expected = MalformedDNSHeaderException.class)
    public void testParseWithInvalidZFieldBits() throws Exception {
        short[] header = {0x0001, 0x0070, 0x0000, 0x0000, 0x0000, 0x0000};
        DNSHeader.tryParse(header);
    }

    @Test
    public void testParseAValidRequestHeader() throws Exception {
        short[] header = {0x0001, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000};
        DNSHeader dnsHeader = DNSHeader.tryParse(header);
        assertEquals(1, dnsHeader.getTransactionID());
        assertTrue(dnsHeader.isQuery());
        assertEquals(OperationType.QUERY, dnsHeader.getOperationType());
        assertFalse(dnsHeader.isTruncated());
        assertFalse(dnsHeader.isAuthorativeAnswer());
        assertTrue(dnsHeader.isRecursionDesired());
        assertEquals(1, dnsHeader.getQuestionsCount());
    }

    @Test
    public void testParseAValidResponseHeader() throws Exception {
        short[] header = {0x0001, (short)0x8180, 0x0001, 0x0001, 0x0000, 0x0000};
        DNSHeader dnsHeader = DNSHeader.tryParse(header);
        assertEquals(1, dnsHeader.getTransactionID());
        assertFalse(dnsHeader.isQuery());
        assertEquals(OperationType.QUERY, dnsHeader.getOperationType());
        assertFalse(dnsHeader.isAuthorativeAnswer());
        assertFalse(dnsHeader.isTruncated());
        assertTrue(dnsHeader.isRecursionDesired());
        assertTrue(dnsHeader.isRecursionAvailable());
        assertEquals(ResponseType.NO_ERROR, dnsHeader.getResponseType());
        assertEquals(1, dnsHeader.getQuestionsCount() );
        assertEquals(1, dnsHeader.getAnswerCount());
        assertEquals(0, dnsHeader.getAuthorityNameserversCount());
        assertEquals(0, dnsHeader.getAdditionalRecordsCount());
    }

    @Test
    public void testToByteArray() throws Exception {
        short[] header = {0x0001, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000};
        DNSHeader dnsHeader = DNSHeader.tryParse(header);
        byte[] bytes = dnsHeader.toBytesArray();
        assertEquals(12, bytes.length);
        assertEquals(0x00, bytes[0]);
        assertEquals(0x01, bytes[1]);
        assertEquals(0x01, bytes[2]);
        assertEquals(0x00, bytes[3]);
        assertEquals(0x00, bytes[4]);
        assertEquals(0x01, bytes[5]);
        assertEquals(0x00, bytes[6]);
        assertEquals(0x00, bytes[7]);
        assertEquals(0x00, bytes[8]);
        assertEquals(0x00, bytes[9]);
        assertEquals(0x00, bytes[10]);
        assertEquals(0x00, bytes[11]);
    }

}