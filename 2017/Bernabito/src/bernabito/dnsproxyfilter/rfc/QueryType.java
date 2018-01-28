package bernabito.dnsproxyfilter.rfc;

/**
 * Autore: Matteo Bernabito
 * Enumeratore per tipi di query definiti in RFC1035 + RFC3596 (AAAA IPv6), sono esclusi i tipi deprecati e sperimentali.
 * Si noti che il codice 0 non è definito e viene utilizzato per farci finire tutte le casistiche non note.
 */

public enum QueryType {
    UNKNOWN(0),
    A(1),
    NS(2),
    CNAME(5),
    SOA(6),
    WKS(11),
    PTR(12),
    HINFO(13),
    MINFO(14),
    MX(15),
    TXT(16),
    AAAA(28),
    AXFR(252),
    MAILB(253),
    MAILA(254),
    ANY(255);

    public final int code;
    QueryType(int code) { this.code = code; }

    public static QueryType fromCode(int code) {
        for(QueryType qT: QueryType.values())
            if(qT.code == code)
                return qT;
        return QueryType.UNKNOWN;
    }
}