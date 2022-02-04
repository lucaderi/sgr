package bernabito.dnsproxyfilter.cli;

import bernabito.dnsproxyfilter.server.DatagramDNSProxy;
import bernabito.dnsproxyfilter.server.DomainFilter;
import bernabito.dnsproxyfilter.server.exceptions.IllegalDomainSyntaxException;
import bernabito.dnsproxyfilter.util.CustomLogger;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import java.io.IOException;
import java.net.SocketException;
import java.util.logging.Handler;
import java.util.logging.Level;

/**
 * Autore: Matteo Bernabito
 * Classe che contiene il main con la Command Line Interface.
 * Per il parsing dei parametri da linea di comando viene utilizzata la libreria JCommander,
 * per ulteriori informazioni: http://jcommander.org/
 */

public class Main {

    public static void main(String args[]) {
        // Parsing dei parametri
        Args parsedArgs = new Args();

        JCommander jCommander = JCommander.newBuilder()
                                .programName("dnsproxyfilter")
                                .addObject(parsedArgs)
                                .build();

        try {
            jCommander.parse(args);
        } catch (ParameterException pe) {
            System.err.println(pe.getMessage());
            System.err.flush();
            jCommander.usage();
            System.exit(-1);
        }

        // Controllo se c'è richiesta con --help
        if(parsedArgs.help) {
            jCommander.usage();
            System.exit(0);
        }

        // Leggo la blacklist, se passata come parametro
        DomainFilter domainFilter = null;
        if(parsedArgs.domainFilterFile != null) {
            try {
                domainFilter = DomainFilter.loadFromFile(parsedArgs.domainFilterFile.getPath());
            } catch (IOException e) {
                System.err.println(e.getMessage());
                System.exit(-1);
            } catch (IllegalDomainSyntaxException e) {
                System.err.println("Invalid blacklist file " + parsedArgs.domainFilterFile.getName());
                System.exit(-1);
            }
        }

        // Setuppo il logger
        CustomLogger.setup(!parsedArgs.debug);
        if(parsedArgs.verbose)
            CustomLogger.getLogger().setLevel(Level.ALL);

        // Setup del server
        try {
            final DatagramDNSProxy datagramDNSProxy = new DatagramDNSProxy(parsedArgs.listeningPort, parsedArgs.bindingAddress, parsedArgs.forwardAddresses, parsedArgs.threadNumber)
                                                        .setDnsReplyTimeout(parsedArgs.dnsReplyTimeout)
                                                        .applyDomainFilter(domainFilter);
            // Starto il server
            datagramDNSProxy.start();
            // Registro lo shutdown hook per una terminazione "pulita"
            // E' possibile che il logger non riesca comunque a loggare a causa dello shutdown hook
            // della classe LogManager di Java che chiude tutti gli handler e dato che gli shutdown hooks sono eseguiti
            // in parallelo non si ha nessuna garanzia di riuscire a loggare in tempo quello che si vuole
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                datagramDNSProxy.interrupt();
                try { datagramDNSProxy.join(); } catch (InterruptedException ignored) {}
                Handler[] handlers = CustomLogger.getLogger().getHandlers();
                for(Handler h : handlers)
                    h.flush();
            }));
            // Joino il thread del server
            datagramDNSProxy.join();
        } catch (SocketException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        } catch (InterruptedException ignored) { }
    }
}
