package bernabito.dnsproxyfilter.rfc;

/**
 * Autore: Matteo Bernabito
 * Classe con alcune proprietà sul protocollo DNS estrapolate dai vari RFC.
 */

public class DNSProperties {

    private DNSProperties() { }

    /** RFC 1035 4.1.1 */
    public final static int HEADER_LENGTH = 6;

    /** RFC 793 */
    public final static int DNS_TCP_PORT = 53;

    /** RFC-768 */
    public final static int DNS_UDP_PORT = 53;

    /** RFC 1035 4.2.1. */
    public final static int UDP_MAX_LENGTH = 512;

}
