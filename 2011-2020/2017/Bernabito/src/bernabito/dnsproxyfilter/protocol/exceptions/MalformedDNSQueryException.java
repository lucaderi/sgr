package bernabito.dnsproxyfilter.protocol.exceptions;

/**
 * Autore: Matteo Bernabito
 * Classe di eccezione lanciata in caso in cui una richiesta DNS sia malformata.
 */

public class MalformedDNSQueryException extends Exception {

    public MalformedDNSQueryException() {
        super("Malformed DNS Query");
    }

    public MalformedDNSQueryException(String message) {
        super(message);
    }

}
