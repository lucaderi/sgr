package bernabito.dnsproxyfilter.cli.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

/**
 * Autore: Matteo Bernabito
 * Validatore per JCommander per il paramtro timeout di risposta dei server DNS.
 */

public class DnsReplyTimeoutValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            int dnsReplyTimeout = Integer.parseInt(value);
            if(dnsReplyTimeout <= 100 || dnsReplyTimeout > 3000)
                throw new ParameterException(("Invalid dns reply timeout " + value + " for parameter " + name + " (Use 100-3000 range)"));
        } catch (NumberFormatException e) {
            throw new ParameterException(("Invalid dns reply timeout " + value + " for parameter " + name));
        }
    }
}
