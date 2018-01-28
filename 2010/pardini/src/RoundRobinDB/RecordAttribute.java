package RoundRobinDB;

public class RecordAttribute implements java.io.Serializable{
	private String attributeName;
	private int maxByteLength;
	
	/**
     * Costruttore della Classe RecordAttribute.
     * @param attributeName nome dell'attributo.
     * @param maxByteLength lunghezza massima in byte dell'attributo. 
     */
    public RecordAttribute(String attributeName, int maxByteLength) {
    	this.attributeName = attributeName;
    	this.maxByteLength = maxByteLength;
    } 
    
    /**
     * Restituisce il nome dell'attributo.
     * @return il nome dell'attributo.
     */
    public String getAttributeName(){
    	return attributeName;
    }
    
    /**
     * Restituisce la lunghezza massima in byte dell'attributo.
     * @return la lunghezza massima in byte dell'attributo.
     */
    public int getMaxByteLength(){
    	return maxByteLength;
    }    
}