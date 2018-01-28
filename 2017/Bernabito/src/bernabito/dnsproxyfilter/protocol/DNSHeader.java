package bernabito.dnsproxyfilter.protocol;

import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSHeaderException;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.rfc.OperationType;
import bernabito.dnsproxyfilter.rfc.ResponseType;
import bernabito.dnsproxyfilter.util.DataConversion;

/**
 * Autore: Matteo Bernabito
 * Classe che rappresenta l'header del protocollo DNS.
 * Fornisce metodi per il parsing e l'estrapolazione dei campi dall'header.
 *
 *                  RFC 1035 Header Format
 *
 *                                   1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *     Z Bits MUST be 0's.
 *
 */

public class DNSHeader {

    private short[] headerData;

    private DNSHeader(short[] headerData) {
        this.headerData = new short[headerData.length];
        System.arraycopy(headerData, 0, this.headerData, 0, headerData.length);
    }

    public static DNSHeader tryParse(short[] headerData) throws MalformedDNSHeaderException {
        if(headerData == null)
            throw new NullPointerException();
        if(headerData.length != DNSProperties.HEADER_LENGTH)
            throw new MalformedDNSHeaderException("Header must be 12 bytes long");
        if(((headerData[1] >>> 4) & 0x0007) != 0)
            throw new MalformedDNSHeaderException("Z field should be all 0's according to RFC1035");
        return new DNSHeader(headerData);
    }

    public int getTransactionID() { return headerData[0]; }

    public boolean isQuery() { return (headerData[1] >>> 15) == 0; }

    public OperationType getOperationType() {
        return OperationType.fromCode((headerData[1] >>> 11) & 0x000f);
    }

    public boolean isAuthorativeAnswer() { return ((headerData[1] >>> 10) & 0x0001) == 1; }

    public boolean isTruncated() { return ((headerData[1] >>> 9) & 0x0001) == 1; }

    public boolean isRecursionDesired() { return ((headerData[1] >>> 8) & 0x0001) == 1; }

    public boolean isRecursionAvailable() { return ((headerData[1] >>> 7) & 0x0001) == 1; }

    public ResponseType getResponseType() {
        return ResponseType.fromCode(headerData[1] & 0x000f);
    }

    public int getQuestionsCount() { return headerData[2]; }

    public int getAnswerCount() { return headerData[3]; }

    public int getAuthorityNameserversCount() { return headerData[4]; }

    public int getAdditionalRecordsCount() { return headerData[5]; }

    public DNSHeader setTransactionID(int id) {
        headerData[0] = (short) id;
        return this;
    }

    public DNSHeader setQuery(boolean isQuery) {
        if(isQuery)
            headerData[1] = (short) (headerData[1] & 0x7fff);
        else
            headerData[1] = (short) (headerData[1] | 0x8000);
        return this;
    }

    public DNSHeader setOperationType(OperationType operationType) {
        if(operationType == null)
            throw new NullPointerException();
        headerData[1] = (short) ((headerData[1] & 0x87ff) | (operationType.code << 11));
        return this;
    }

    public DNSHeader setAuthorativeAnswer(boolean authorativeAnswer) {
        if(authorativeAnswer)
            headerData[1] = (short) (headerData[1] | 0x0400);
        else
            headerData[1] = (short) (headerData[1] & 0xfbff);
        return this;
    }

    public DNSHeader setTruncated(boolean truncated) {
        if(truncated)
            headerData[1] = (short) (headerData[1] | 0x0200);
        else
            headerData[1] = (short) (headerData[1] & 0xfdff);
        return this;
    }

    public DNSHeader setRecursionDesired(boolean recursionDesired) {
        if(recursionDesired)
            headerData[1] = (short) (headerData[1] | 0x0100);
        else
            headerData[1] = (short) (headerData[1] & 0xfeff);
        return this;
    }

    public DNSHeader setRecursionAvailable(boolean recursionAvailable) {
        if(recursionAvailable)
            headerData[1] = (short) (headerData[1] | 0x0080);
        else
            headerData[1] = (short) (headerData[1] & 0x0070);
        return this;
    }

    public DNSHeader setResponseType(ResponseType responseType) {
        if(responseType == null)
            throw new NullPointerException();
        headerData[1] = (short) ((headerData[1] & 0xfff0) | responseType.code);
        return this;
    }

    public DNSHeader setQuestionsCount(int questionsCount) {
        headerData[2] = (short) questionsCount;
        return this;
    }

    public DNSHeader setAnswerCount(int answerCount) {
        headerData[3] = (short) answerCount;
        return this;
    }

    public DNSHeader setAuthorityNameserversCount(int authorityNameserversCount) {
        headerData[4] = (short) authorityNameserversCount;
        return this;
    }

    public DNSHeader setAdditionalRecordsCount(int additionalRecordsCount) {
        headerData[5] = (short) additionalRecordsCount;
        return this;
    }

    public byte[] toBytesArray() {
        byte[] byteArray = new byte[headerData.length * 2];
        for(int i=0; i<headerData.length; i++) {
            byte[] converted = DataConversion.convertShortToByteArray(headerData[i]);
            System.arraycopy(converted, 0, byteArray, i*2, 2);
        }
        return byteArray;
    }
}
