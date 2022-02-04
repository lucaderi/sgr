package bernabito.dnsproxyfilter.server.exceptions;

/**
 * Autore: Matteo Bernabito
 * Classe di eccezione lanciata nel caso in cui un dominio non abbia una sintassi valida.
 */

public class IllegalDomainSyntaxException extends Exception {

    public IllegalDomainSyntaxException() {
        super("Illegal domain syntax");
    }

    public IllegalDomainSyntaxException(String msg) {
        super(msg);
    }

}
