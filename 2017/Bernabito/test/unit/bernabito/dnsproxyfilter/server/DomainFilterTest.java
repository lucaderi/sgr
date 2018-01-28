package unit.bernabito.dnsproxyfilter.server;

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
 * Classe di unit testing per DomainFilter.
 */

public class DomainFilterTest {

    private DomainFilter domainFilter;

    @Before
    public void setUp() throws Exception {
        domainFilter = new DomainFilter();
    }

    @Test(expected = IllegalDomainSyntaxException.class)
    public void testAddFilteredDomainWithEmptyDomain() throws Exception {
        domainFilter.addFilteredDomain("");
    }

    @Test(expected = IllegalDomainSyntaxException.class)
    public void testAddFilteredDomainWithInvalidDomain() throws Exception {
        domainFilter.addFilteredDomain("prova..hello.it");
    }

    @Test
    public void testAddFilteredDomainsWithSomeDomains() throws Exception {
        String d0 = "google.com";
        String d1 = "google.it";
        String d2 = "wikipedia.com";
        domainFilter.addFilteredDomain(d0);
        domainFilter.addFilteredDomain(d1);
        domainFilter.addFilteredDomain(d2);
        assertTrue(domainFilter.isFiltered(d0));
        assertTrue(domainFilter.isFiltered(d1));
        assertTrue(domainFilter.isFiltered(d2));
    }

    @Test
    public void testAddFilteredDomainsWithWildcards() throws Exception {
        String w0 = "*.google.com";
        domainFilter.addFilteredDomain(w0);
        assertTrue(domainFilter.isFiltered("google.com"));
        assertTrue(domainFilter.isFiltered("drive.google.com"));
        assertFalse(domainFilter.isFiltered("wikipedia.com"));
    }

    @Test
    public void testAddFilteredDomainsWithGlobalWildcardThatBlocksEverything() throws Exception {
        String blockAll = "*";
        domainFilter.addFilteredDomain(blockAll);
        assertTrue(domainFilter.isFiltered("google.it"));
        assertTrue(domainFilter.isFiltered("wikipedia.com"));
        assertTrue(domainFilter.isFiltered("pippo.pluto.co.uk"));
    }

    @Test
    public void testAddFilteredDomainSubdomainsShouldNotBlockMainDomain() throws Exception {
        String d0 = "drive.google.it";
        String d1 = "google.it";
        domainFilter.addFilteredDomain(d0);
        assertTrue(domainFilter.isFiltered(d0));
        assertFalse(domainFilter.isFiltered(d1));
    }

    @Test
    public void testAddFiltereDomainASubdomainAndMainDomainShouldNotBlockOtherSubdomains() throws Exception {
        String d0 = "drive.google.it";
        String d1 = "google.it";
        domainFilter.addFilteredDomain(d0);
        domainFilter.addFilteredDomain(d1);
        assertTrue(domainFilter.isFiltered(d0));
        assertTrue(domainFilter.isFiltered(d1));
        assertFalse(domainFilter.isFiltered("gmail.google.it"));
    }

    @Test
    public void testClearAllDomainsInFilter() throws Exception {
        String d0 = "google.com";
        String d1 = "google.it";
        domainFilter.addFilteredDomain(d0);
        domainFilter.addFilteredDomain(d1);
        assertTrue(domainFilter.isFiltered(d0));
        assertTrue(domainFilter.isFiltered(d1));
        domainFilter.clearAll();
        assertFalse(domainFilter.isFiltered(d0));
        assertFalse(domainFilter.isFiltered(d1));
    }

}