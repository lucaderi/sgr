package bernabito.dnsproxyfilter.protocol.exceptions;

/**
 * Autore: Matteo Bernabito
 * Classe di eccezione lanciata in caso di protocollo non riconosciuto.
 */

public class MismatchingProtocolException extends Exception {

    public MismatchingProtocolException() {
        super("Protocol does not match");
    }

    public MismatchingProtocolException(String message) {
        super(message);
    }

}
