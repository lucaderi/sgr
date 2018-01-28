package bernabito.dnsproxyfilter.rfc;

/**
 * Autore: Matteo Bernabito
 * Enumeratore per il "tipo di risposta" usato nelle risposte DNS.
 */

public enum ResponseType {
    NO_ERROR(0),
    FORMAT_ERROR(1),
    SERVER_FAILURE(2),
    NAME_ERROR(3),
    NOT_IMPLEMENTED(4),
    REFUSED(5),
    RESERVED(6);

    public final int code;
    ResponseType(int code) {
        this.code = code;
    }

    public static ResponseType fromCode(int code) {
        if(code >= ResponseType.values().length)
            return ResponseType.RESERVED;
        else
            return ResponseType.values()[code];
    }
}
