package bernabito.dnsproxyfilter.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Autore: Matteo Bernabito
 * Classe per la formattazione dei record di log.
 */

public class CustomFormatter extends Formatter {

    private static final DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy, HH:mm:ss");

    @Override
    public String format(LogRecord record) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(dateFormat.format(new Date()));
        buffer.append(" - ");
        buffer.append(record.getLevel());
        buffer.append(" - Thread ");
        buffer.append(record.getThreadID());
        buffer.append(" - ");
        buffer.append(record.getSourceClassName());
        buffer.append(" - ");
        buffer.append(record.getMessage());
        buffer.append(System.getProperty("line.separator"));
        return buffer.toString();
    }

}
