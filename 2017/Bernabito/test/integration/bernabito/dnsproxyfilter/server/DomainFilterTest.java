package integration.bernabito.dnsproxyfilter.server;


import bernabito.dnsproxyfilter.server.DomainFilter;
import bernabito.dnsproxyfilter.server.exceptions.IllegalDomainSyntaxException;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import static org.junit.Assert.*;

/**
 * Autore: Matteo Bernabito
 * Test di integrazione per DomainFilter, si testa la lettura di filtri da file.
 */

public class DomainFilterTest {

    private DomainFilter domainFilter;

    @Before
    public void setUp() throws Exception {
        domainFilter = new DomainFilter();
    }

    @Test
    public void testLoadFromFileWithValidSetOfDomains() throws Exception{
        File file = File.createTempFile("FilteredDomains", "tmp");
        file.deleteOnExit();
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));
        String[] validFilteredDomainsSet = {"google.it", "drive.google.it", "*.co.uk"};
        for(String s : validFilteredDomainsSet) {
            bufferedWriter.write(s);
            bufferedWriter.newLine();
        }
        bufferedWriter.flush();
        bufferedWriter.close();
        DomainFilter domainFilter = DomainFilter.loadFromFile(file.getPath());
        assertTrue(domainFilter.isFiltered("google.it"));
        assertFalse(domainFilter.isFiltered("google.com"));
        assertTrue(domainFilter.isFiltered("drive.google.it"));
        assertFalse(domainFilter.isFiltered("gmail.google.it"));
        assertTrue(domainFilter.isFiltered("hello.co.uk"));
        assertTrue(domainFilter.isFiltered("whatever.co.uk"));
    }

    @Test
    public void testLoadFromFileWithValidSetOfDomainsWithDoubleLineFeeds() throws Exception {
        File file = File.createTempFile("FancyFilteredDomains", "tmp");
        file.deleteOnExit();
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));
        String[] validFilteredDomainsSet = {"google.it", "drive.google.it", "*.co.uk"};
        for(String s : validFilteredDomainsSet) {
            bufferedWriter.write(s);
            bufferedWriter.newLine();
            bufferedWriter.newLine();
        }
        bufferedWriter.flush();
        bufferedWriter.close();
        DomainFilter domainFilter = DomainFilter.loadFromFile(file.getPath());
        assertTrue(domainFilter.isFiltered("google.it"));
        assertFalse(domainFilter.isFiltered("google.com"));
        assertTrue(domainFilter.isFiltered("drive.google.it"));
        assertFalse(domainFilter.isFiltered("gmail.google.it"));
        assertTrue(domainFilter.isFiltered("hello.co.uk"));
        assertTrue(domainFilter.isFiltered("whatever.co.uk"));
    }

    @Test
    public void testLoadFromFileWithInvalidEntry() throws Exception {
        File file = File.createTempFile("TypoDomains", "tmp");
        file.deleteOnExit();
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));
        String[] validFilteredDomainsSet = {"google.it", "invalid..google.it", "*.co.uk"};
        for(String s : validFilteredDomainsSet) {
            bufferedWriter.write(s);
            bufferedWriter.newLine();
        }
        bufferedWriter.flush();
        bufferedWriter.close();
        try {
            DomainFilter.loadFromFile(file.getPath());
            fail("It should throw a IllegalDomainSyntaxException");
        } catch (IllegalDomainSyntaxException e) {
            assertEquals("Illegal domain syntax at line 2", e.getMessage());
        }
    }
}
