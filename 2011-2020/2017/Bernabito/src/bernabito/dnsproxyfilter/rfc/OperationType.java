package bernabito.dnsproxyfilter.rfc;

/**
 * Autore: Matteo Bernabito
 * Enumeratore per il tipo di operazione presente nell'header.
 */

public enum OperationType {
    QUERY(0),
    IQUERY(1),
    STATUS(2),
    RESERVED(3);

    public final int code;
    OperationType(int code) {
        this.code = code;
    }

    public static OperationType fromCode(int code) {
        if(code >= OperationType.values().length)
            return OperationType.RESERVED;
        else
            return OperationType.values()[code];
    }
}
