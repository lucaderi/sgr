package bernabito.dnsproxyfilter.util;

/**
 * Autore: Matteo Bernabito
 * Classe di utilità per la conversione di dati.
 */

public class DataConversion {

    private DataConversion() { }

    public static byte[] convertShortToByteArray(short value) {
        byte[] bytes = new byte[2];
        bytes[0] = (byte) (value >>> 8);
        bytes[1] = (byte) (value & 0x00ff);
        return bytes;
    }

}
