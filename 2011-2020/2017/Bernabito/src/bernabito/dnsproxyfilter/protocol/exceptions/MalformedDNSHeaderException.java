package bernabito.dnsproxyfilter.protocol.exceptions;

/**
 * Autore: Matteo Bernabito
 * Classe di eccezione lanciata nel caso in cui l'header DNS sia malformato.
 */

public class MalformedDNSHeaderException extends Exception {

    public MalformedDNSHeaderException() {
        super("Malformed DNS Header");
    }

    public MalformedDNSHeaderException(String message) {
        super(message);
    }

}
