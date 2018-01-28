package unit.bernabito.dnsproxyfilter.protocol;

import bernabito.dnsproxyfilter.protocol.DNSQuery;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSHeaderException;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSQueryException;
import bernabito.dnsproxyfilter.protocol.exceptions.MismatchingProtocolException;
import bernabito.dnsproxyfilter.rfc.QueryClass;
import bernabito.dnsproxyfilter.rfc.QueryType;
import bernabito.dnsproxyfilter.protocol.DNSHeader;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;

import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * Autore: Matteo Bernabito
 * Classe di unit testing per DNSQuery.
 * Mocking della classe DNSHeader per rendere il test indipendente.
 */


@RunWith(PowerMockRunner.class)
@PrepareForTest(DNSHeader.class)
public class DNSQueryTest {

    private DNSHeader mockHeader;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(DNSHeader.class);
        mockHeader = Mockito.mock(DNSHeader.class);
        Mockito.when(DNSHeader.tryParse(any())).thenReturn(mockHeader);
    }

    @Test
    public void testParseAValidQuery() throws Exception {
        Mockito.when(mockHeader.isQuery()).thenReturn(true);
        Mockito.when(mockHeader.getQuestionsCount()).thenReturn(1);
        byte[] validQuery = {0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        DNSQuery query = DNSQuery.tryParse(new ByteArrayInputStream(validQuery));
        assertEquals("google.it", query.getQueryString());
        assertEquals(QueryType.A, query.getQueryType());
        assertEquals(QueryClass.IN, query.getQueryClass());
    }

    @Test
    public void testParseAResponse() {
        Mockito.when(mockHeader.isQuery()).thenReturn(false);
        try {
            byte[] validResponse = {0x00, 0x02, (byte) 0x81, (byte) 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f,
                    0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, (byte) 0xc0, 0x0c, 0x00,
                    0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b, 0x00, 0x04, (byte) 0xd8, 0x3a, (byte) 0xc6, 0x23};
            DNSQuery.tryParse(new ByteArrayInputStream(validResponse));
            fail("This should throw a MalformedDNSQueryException");
        } catch (IOException | MalformedDNSHeaderException | MismatchingProtocolException e) {
            fail(e.getMessage());
        } catch (MalformedDNSQueryException e) {
            assertEquals("Message must be a query, not a response", e.getMessage());
        }
    }

    @Test
    public void testParseQueryWithMultipleRequests() {
        Mockito.when(mockHeader.isQuery()).thenReturn(true);
        Mockito.when(mockHeader.getQuestionsCount()).thenReturn(2);
        byte[] queryWithTwoQuestions = {0x00, 0x02, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        try {
            DNSQuery.tryParse(new ByteArrayInputStream(queryWithTwoQuestions));
            fail("This should throw a MalformedDNSQueryException");
        } catch (IOException | MalformedDNSHeaderException | MismatchingProtocolException e) {
            fail(e.getMessage());
        } catch (MalformedDNSQueryException e) {
            assertEquals("Invalid questions count", e.getMessage());
        }
    }

    @Test(expected = MismatchingProtocolException.class)
    public void testParseQueryWithJustAByte() throws Exception {
        byte[] oneByte = {(byte)0xff};
        DNSQuery.tryParse(new ByteArrayInputStream(oneByte));
    }

    @Test
    public void testParseQueryWithExceedingBytes() {
        Mockito.when(mockHeader.isQuery()).thenReturn(true);
        Mockito.when(mockHeader.getQuestionsCount()).thenReturn(1);
        byte[] invalidTooLongQuery = {0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00};
        try {
            DNSQuery.tryParse(new ByteArrayInputStream(invalidTooLongQuery));
            fail("This should throw a MalformedDNSQueryException");
        }  catch (MismatchingProtocolException | MalformedDNSHeaderException | IOException e) {
            fail(e.getMessage());
        }  catch (MalformedDNSQueryException e) {
            assertEquals("Request contains too many bytes", e.getMessage());
        }
    }

    @Test
    public void testToBytesArray() throws Exception {
        Mockito.when(mockHeader.isQuery()).thenReturn(true);
        Mockito.when(mockHeader.getQuestionsCount()).thenReturn(1);
        Mockito.when(mockHeader.toBytesArray()).thenReturn(new byte[]{0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        byte[] validQuery = {0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
                0x67, 0x6c, 0x65, 0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01};
        DNSQuery query = DNSQuery.tryParse(new ByteArrayInputStream(validQuery));
        assertArrayEquals(validQuery, query.toByteArray());
    }
}