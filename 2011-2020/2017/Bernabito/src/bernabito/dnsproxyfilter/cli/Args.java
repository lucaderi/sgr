package bernabito.dnsproxyfilter.cli;

import bernabito.dnsproxyfilter.cli.validators.*;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.server.DatagramDNSProxy;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.InetAddressConverter;

import java.io.File;
import java.net.InetAddress;
import java.util.List;

/**
 * Autore: Matteo Bernabito
 * Classe per JCommander, rappresenta i parametri passabili alla CLI.
 */

class Args {

    @Parameter(names = {"-p", "-port"}, description = "Server listening port", validateWith = PortValidator.class)
    int listeningPort = DNSProperties.DNS_UDP_PORT;

    @Parameter(names = {"-b", "-bind"}, description = "Server binding address, wildcard if not specified",
            converter = InetAddressConverter.class,
            validateWith = InetAddressValidator.class)
    InetAddress bindingAddress = null;

    @Parameter(names = {"-f", "-forward"}, description = "Comma separated list of forwarding DNS servers, Google servers if not specified",
            converter = InetAddressConverter.class,
            validateWith = InetAddressListValidator.class)
    List<InetAddress> forwardAddresses = null;

    @Parameter(names = {"-d", "-domainfilter"}, description = "File path containing domain blacklist")
    File domainFilterFile = null;

    @Parameter(names = {"-debug"}, description = "Disable logging on file and enable all messages on command line")
    boolean debug = false;

    @Parameter(names = {"-v", "-verbose"}, description = "Increase log verbosity, -debug option activate this by default")
    boolean verbose = false;

    @Parameter(names = {"-t", "-thread"}, description = "Number of threads handling concurrent connections",
            validateWith = ThreadNumberValidator.class)
    int threadNumber = DatagramDNSProxy.DEFAULT_THREAD_POOL_SIZE;

    @Parameter(names = {"-r", "-replytimeout"}, description = "Number of maximum milliseconds to wait for a DNS server to answer",
            validateWith = DnsReplyTimeoutValidator.class)
    int dnsReplyTimeout = DatagramDNSProxy.DEFAULT_DNS_REPLY_TIMEOUT;

    @Parameter(names = {"--help"}, description = "Show this message", help = true)
    boolean help = false;

}
