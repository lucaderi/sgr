package bernabito.dnsproxyfilter.protocol;

import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSHeaderException;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSQueryException;
import bernabito.dnsproxyfilter.protocol.exceptions.MismatchingProtocolException;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.rfc.QueryClass;
import bernabito.dnsproxyfilter.rfc.QueryType;
import bernabito.dnsproxyfilter.util.DataConversion;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * Autore: Matteo Bernabito
 * Classe che rappresenta una richiesta DNS.
 * Fornisce metodi per il parsing e l'estrapolazione dei campi della richiesta.
 *
 *   RFC 1035 generic message format (query and response)
 *
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 *
 *  RFC 1035 question format
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  |                     QNAME                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

public class DNSQuery {

    private DNSHeader header;
    private String queryString;
    private QueryType queryType;
    private QueryClass queryClass;

    private DNSQuery(DNSHeader header, String queryString, QueryType queryType, QueryClass queryClass) {
        this.header = header;
        this.queryString = queryString;
        this.queryType = queryType;
        this.queryClass = queryClass;
    }

    public static DNSQuery tryParse(ByteArrayInputStream byteInputStream) throws MalformedDNSQueryException, MismatchingProtocolException, MalformedDNSHeaderException, IOException {
        if(byteInputStream == null)
            throw new NullPointerException();
        short[] header = new short[DNSProperties.HEADER_LENGTH];

        try (DataInputStream dataInputStream = new DataInputStream(byteInputStream)) {
            // Leggo l'header
            for (int i = 0; i < header.length; i++)
                header[i] = dataInputStream.readShort();
            // Provo a parsare l'header
            DNSHeader parsedHeader = DNSHeader.tryParse(header);
            // Controllo se il messaggio è una query
            if(!parsedHeader.isQuery())
                throw new MalformedDNSQueryException("Message must be a query, not a response");
            // Nonostante nell'RFC 1035 è specificato che possono essere fatte piu richieste nello stesso messaggio
            // nella realtà dei fatti questo non avviene mai a causa di ambiguità semantiche e i server DNS non lo supportano, come chiarito qui:
            // https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query
            // Quindi, nel caso in cui sono indicate nell'header 0 o più di 1 domande, lancio un'eccezione
            if(parsedHeader.getQuestionsCount() != 1)
                throw new MalformedDNSQueryException("Invalid questions count");
            // Provo a parsare la richiesta
            String queryString = "";
            byte labelLength;
            while((labelLength = dataInputStream.readByte()) != 0) {
                if((labelLength >>> 6) != 0) // Gli ultimi 2 bit devono essere 0 (lunghezza tra 0 e 2^6)
                    throw new MalformedDNSQueryException("Label length bit 7 and 8 must be 0's");
                byte[] label = new byte[labelLength];
                if(dataInputStream.read(label, 0, labelLength) != labelLength)
                    throw new MalformedDNSQueryException("Not enough label bytes in query string");
                queryString = queryString.concat(new String(label)).concat(".");
            }
            if(queryString.isEmpty())
                throw new MalformedDNSQueryException("Empty request");
            // Rimuovo il punto di troppo in fondo
            queryString = queryString.substring(0, queryString.length() - 1);
            // Leggo gli ultimi due campi
            QueryType queryType = QueryType.fromCode(dataInputStream.readShort());
            QueryClass queryClass = QueryClass.fromCode(dataInputStream.readShort());
            // Controllo se rimangono byte da leggere, NON dovrebbe esserci altro
            if(dataInputStream.available() != 0)
                throw new MalformedDNSQueryException("Request contains too many bytes");
            return new DNSQuery(parsedHeader, queryString, queryType, queryClass);
        } catch (EOFException e) {
            throw new MismatchingProtocolException();
        }
    }

    public DNSHeader getHeader() {
        return header;
    }

    public String getQueryString() {
        return queryString;
    }

    public QueryType getQueryType() {
        return queryType;
    }

    public QueryClass getQueryClass() {
        return queryClass;
    }

    public byte[] toByteArray() {
        byte[] headerPart = header.toBytesArray();
        // +6 perchè 4 byte sono il QTYPE e il QCLASS e 2 sono il terminatore del root label piu uno iniziale
        int bodyPartLength = (queryString.length() + 6);
        byte[] total = new byte[headerPart.length + bodyPartLength];
        System.arraycopy(headerPart, 0, total, 0, headerPart.length);
        String[] labels = queryString.split("\\.");
        int i = headerPart.length;
        for(String label : labels) {
            total[i] = (byte) label.length();
            i++;
            for(int j=0; j<label.length(); j++) {
                total[i] = (byte) label.charAt(j);
                i++;
            }
        }
        // Terminatore
        total[i] = 0x00;
        i++;
        byte[] queryType = DataConversion.convertShortToByteArray((short)this.queryType.code);
        byte[] queryClass = DataConversion.convertShortToByteArray((short)this.queryClass.code);
        System.arraycopy(queryType, 0, total, i, queryType.length);
        System.arraycopy(queryClass, 0, total, i+2, queryClass.length);
        return total;
    }
}
