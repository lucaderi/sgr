package bernabito.dnsproxyfilter.rfc;

/**
 * Autore: Matteo Bernabito
 * Enumeratore delle classi di query definiti in RFC1035, sono esclusi i tipi deprecati e sperimentali.
 */

public enum QueryClass {
    UNKNOWN(0),
    IN(1),
    CH(3),
    HS(4),
    ANY(255);

    public final int code;
    QueryClass(int code) { this.code = code; }

    public static QueryClass fromCode(int code) {
        for(QueryClass qC: QueryClass.values())
            if(qC.code == code)
                return qC;
        return QueryClass.UNKNOWN;
    }
}