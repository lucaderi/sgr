package bernabito.dnsproxyfilter.util;

import java.io.IOException;
import java.util.logging.*;

/**
 * Autore: Matteo Bernabito
 * Classe per il setup del logger.
 */

public class CustomLogger {

    private static Logger logger;
    private static String LOGGER_FILE_NAME = "dnsproxyfilter.log";

    private CustomLogger() { }

    public static Logger setup(boolean production) {
        logger = Logger.getLogger("Custom Project Logger");
        logger.setUseParentHandlers(false);
        Handler handler;
        if(!production) {
            handler = buildStandardOutputHandler();
        }
        else {
            try {
                handler = buildFileOutputHanlder();
            } catch (IOException e) {
                System.err.println("Error opening log file, message: " + e.getMessage());
                return logger;
            }
        }
        // A livello di handler setto ALL
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        // A livello di logging setto a seconda se sono in debug mode
        if(production)
          logger.setLevel(Level.WARNING);
        else
          logger.setLevel(Level.ALL);
        return logger;
    }

    public static Logger getLogger() {
        if(logger == null)
            setup(false);
        return logger;
    }

    private static Handler buildStandardOutputHandler() {
        return new StreamHandler(System.out, new CustomFormatter()) {
            @Override
            public synchronized void publish(final LogRecord record) {
                super.publish(record);
                flush();
            }
        };
    }

    private static Handler buildFileOutputHanlder() throws IOException {
      FileHandler fileHandler = new FileHandler(LOGGER_FILE_NAME, true);
      fileHandler.setFormatter(new CustomFormatter());
      return fileHandler;
    }

}
