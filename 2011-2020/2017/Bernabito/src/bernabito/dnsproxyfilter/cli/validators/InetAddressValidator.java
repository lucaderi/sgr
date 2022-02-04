package bernabito.dnsproxyfilter.cli.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Autore: Matteo Bernabito
 * Validatore per JCommander per il tipo "indirizzo ip".
 */

public class InetAddressValidator implements IParameterValidator{
    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            throw new ParameterException("Invalid address " + value + " for parameter " + name);
        }
    }
}
