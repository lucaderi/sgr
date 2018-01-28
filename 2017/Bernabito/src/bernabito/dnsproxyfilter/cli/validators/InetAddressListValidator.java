package bernabito.dnsproxyfilter.cli.validators;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Autore: Matteo Bernabito
 * Validatore per JCommander per il tipo "lista di indirizzi ip".
 */

public class InetAddressListValidator implements IParameterValidator{
    @Override
    public void validate(String name, String value) throws ParameterException {
        String[] addresses = value.split(",");
        for(String addr : addresses) {
            try {
                InetAddress.getByName(addr);
            } catch (UnknownHostException e) {
                throw new ParameterException("Invalid address " + addr + " for parameter " + name);
            }
        }
    }
}
