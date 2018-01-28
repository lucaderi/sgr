package bernabito.dnsproxyfilter.cli.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

/**
 * Auotore: Matteo Bernabito
 * Validatore per JCommander per il numero di thread passati come parametro.
 */

public class ThreadNumberValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            int threadNumber = Integer.parseInt(value);
            if(threadNumber <= 0 || threadNumber > 128)
                throw new ParameterException(("Invalid thread number " + value + " for parameter " + name + " (Use 1-128 range)"));
        } catch (NumberFormatException e) {
            throw new ParameterException(("Invalid thread number " + value + " for parameter " + name));
        }
    }
}
