package RoundRobinDB;

public class DBStructure implements java.io.Serializable{
	private String DBname;
	private int timeStep;
	private int timeTollerance;
	private int storageSlots;
	private DBAggregatedStructure[] DBASs = null;
	private int maxRecordForTimeStep;
	private RecordAttribute[] RS = null;
	private int maxByteLengthBetweenAllRecordAttributes;
	private int byteLengthForOneRecord;
	
	
	/**
     * Costruttore della Classe DBStructor.
     * Da utilizzare nel caso si vogliano utilizzare DataBase Aggregati.
     * @param DBname nome del DataBase da Creare.
     * @param timeStep intervallo di tempo in cui è atteso un inserimento di Record.
     * @param timeTollerace tollercanza entro cui il valore viene accettato per un determinato slot.
     * (deve essere strettamente minore di timeStep - altrimenti viene sollevata un eccezione).
     * @param storageSlots numero di slot di memorizzazione del database.
     * @param DBASs array di strutture dati rappresentanti i DataBase Aggregati.
     * (i nomi dei vari DataBase devono essere univoci - altrimenti viene sollevata un eccezione).
     * (i DataBase da Aggregare specificati devono esistere - altrimenti viene sollevata un eccezione).
     * (gli slot da aggregare devono essere minori o uguali al numero degli storageSlots 
     * del DataBase da agregare - altrimenti viene sollevata un eccezione).
     * @param maxRecordForTimeStep massimo numero di record per intervallo temporale.
     * @param RS array di strutture dati rappresentanti un record.
     * @exception IllegalArgumentException se uno degli argomenti passati non è valido.  
     */
    public DBStructure(String DBname, int timeStep, int timeTollerance, int storageSlots,
    DBAggregatedStructure[] DBASs, int maxRecordForTimeStep, RecordAttribute[] RS) throws IllegalArgumentException{
    	if(timeTollerance >= timeStep) throw new IllegalArgumentException( );
    	for(int i = 0; i < DBASs.length; i++){
    		if(DBname.equals(DBASs[i].getDBname())) throw new IllegalArgumentException( );
    		if(i != (DBASs.length-1)){
	    		for(int j = (i+1); j < DBASs.length; j++){
	    			if(DBASs[i].getDBname().equals(DBASs[j].getDBname())) throw new IllegalArgumentException( );
    			}
    		}
    		
    		if(DBASs[i].getDBToAggregate().equals(DBname)){
    			if(DBASs[i].getSlotsToAggregate() > storageSlots) throw new IllegalArgumentException( );   			
    		}else{
    			for(int z = 0; z < DBASs.length; z++ ){
	    			if(DBASs[i].getDBToAggregate().equals(DBASs[z].getDBname())){
	    				if(DBASs[i].getSlotsToAggregate() > DBASs[z].getStorageSlots()) throw new IllegalArgumentException( );
	    				else z = DBASs.length;
	    			}else{
	    				//perchè hai specificato di voler aggregare un DB che non esiste
	    				if(z == (DBASs.length-1)) throw new IllegalArgumentException( );
	    			}
	    		}
    		}    		
    	}
    	this.DBname = DBname;
    	this.timeStep = timeStep;
    	this.timeTollerance = timeTollerance;
    	this.storageSlots = storageSlots;
    	this.DBASs = DBASs;
    	this.maxRecordForTimeStep = maxRecordForTimeStep;
    	this.RS = RS;
    	int tmp = RS[0].getMaxByteLength();
    	this.byteLengthForOneRecord = tmp;
    	for(int j = 1; j < RS.length; j++){
    		if(tmp < RS[j].getMaxByteLength()){
    			tmp = RS[j].getMaxByteLength();
    		}
    		this.byteLengthForOneRecord = this.byteLengthForOneRecord + RS[j].getMaxByteLength();
    	}
    	this.maxByteLengthBetweenAllRecordAttributes = tmp;
    }
    
    /**
     * Costruttore della Classe DBStructor.
     * Da utilizzare nel caso non si vogliano utilizzare DataBase Aggregati.
     * @param DBname nome del DataBase da Creare.
     * @param timeStep intervallo di tempo entro cui è atteso un inserimento di un Record.
     * @param timeTollerace tollercanza entro cui il valore viene accettato per un determinato slot.
     * (deve essere strettamente minore di timeStep - altrimenti viene sollevata un eccezione).
     * @param storageSlots numero di slot di memorizzazione del database.
     * @param maxRecordForTimeStep massimo numero di record per intervallo temporale.
     * @param RS array di strutture dati rappresentanti un record.
     * @exception IllegalArgumentException se uno degli argomenti passati non è valido.  
     */
    public DBStructure(String DBname, int timeStep, int timeTollerace, int storageSlots,
    int maxRecordForTimeStep, RecordAttribute[] RS) throws IllegalArgumentException{
    	if(timeTollerance >= timeStep) throw new IllegalArgumentException( );
    	this.DBname = DBname;
    	this.timeStep = timeStep;
    	this.timeTollerance = timeTollerance;
    	this.storageSlots = storageSlots;
    	this.maxRecordForTimeStep = maxRecordForTimeStep;
    	this.RS = RS;
    	int tmp = RS[0].getMaxByteLength();
    	this.byteLengthForOneRecord = tmp;
    	for(int j = 1; j < RS.length; j++){
    		if(tmp < RS[j].getMaxByteLength()){
    			tmp = RS[j].getMaxByteLength();
    		}
    		this.byteLengthForOneRecord = this.byteLengthForOneRecord + RS[j].getMaxByteLength();
    	}
    	this.maxByteLengthBetweenAllRecordAttributes = tmp;
    }
    
    /**
     * Restituisce il nome del DataBase.
     * @return il nome del DataBase.
     */
    public String getDBname(){
    	return DBname;
    }
    
    /**
     * Restituisce l'intervallo di tempo entro cui è atteso un inserimento di un Record.
     * @return l'intervallo di tempo in cui è atteso un inserimento di Record.
     */
    public int getTimeStep(){
    	return timeStep;
    }
    
    /**
     * Restituisce la tollercanza entro cui il valore viene accettato per un determinato slot.
     * @return la tollercanza entro cui il valore viene accettato per un determinato slot.
     */
    public int getTimeTollerance(){
    	return timeTollerance;
    }
    
    /**
     * Restituisce il numero di slot di memorizzazione del database.
     * @return il numero di slot di memorizzazione del database.
     */
    public int getStorageSlots(){
    	return storageSlots;
    }
    
    /**
     * Restituisce un array di strutture dati rappresentanti i DataBase Aggregati.
     * oppure null nel caso non ci siano DataBase Aggregati.
     * @return un array di strutture dati rappresentanti i DataBase Aggregati.
     */
    public DBAggregatedStructure[] getDBASs(){
    	return DBASs;
    }
    
    /**
     * Restituisce il massimo numero di record per intervallo temporale.
     * @return il massimo numero di record per intervallo temporale.
     */
    public int getMaxRecordForTimeStep(){
    	return maxRecordForTimeStep;
    } 
    	
    /**
     * Restituisce un array di strutture dati rappresentanti un record.
     * @return un array di strutture dati rappresentanti un record.
     */
    public RecordAttribute[] getRecordStructure(){
    	return RS;
    }
    
    /**
     * Restituisce la lunghezza in byte dell'attributo più grande.
     * @return la lunghezza in byte dell'attributo più grande.
     */
    public int getMaxByteLengthBetweenAllRecordAttributes(){
    	return maxByteLengthBetweenAllRecordAttributes;
    }
    
    /**
     * Restituisce il numero di attributi per Record.
     * @return il numero di attributi per Record.
     */
    public int getNumberOfAttributesPerRecord(){
    	return RS.length;
    }
    
    /**
     * Restituisce la lunghezza in byte del Seek Step.
     * @return la lunghezza in byte del Seek Step.
     */
    public int getSeekStep(){
    	return (byteLengthForOneRecord+(4*RS.length))*maxRecordForTimeStep;
    }                      
}