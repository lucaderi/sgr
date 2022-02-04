package bernabito.dnsproxyfilter.cli.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

/**
 * Autore: Matteo Bernabito
 * Validatore per JCommander per il tipo "porta".
 */

public class PortValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            int portNumber = Integer.parseInt(value);
            if(portNumber <= 0 || portNumber > 65535)
                throw new ParameterException(("Invalid port number " + value + " for parameter " + name));
        } catch (NumberFormatException e) {
            throw new ParameterException(("Invalid port number " + value + " for parameter " + name));
        }
    }
}
