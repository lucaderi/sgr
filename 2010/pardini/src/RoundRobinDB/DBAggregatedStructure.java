package RoundRobinDB;

public class DBAggregatedStructure implements java.io.Serializable{
	private String DBname;
	private String DBToAggregate;
	private int slotsToAggregate;
	private int eachTime;
	private AggregationInterface aggregationFunction;
	private int storageSlots;
	
	/**
     * Costruttore della Classe DBAggregatedStructor.
     * @param DBname nome del DataBase Aggregato da Creare.
     * (il nome del DataBase deve essere univoco - altrimenti 
     * verrà sollevata un eccezione in fase di creazione della DBStructure).
     * @param DBToAggregated nome del DataBase da aggregare. 
     * Può essere il DataBase Principale oppure un'altro DataBase Aggregato.
     * (il DataBase deve esistere -  altrimenti verrà sollevata un eccezione in fase di creazione della DBStructure).
     * @param slotsToAggregate il numero di slots del DataBase da Aggregare che vanno aggregati.
     * (gli slot da aggregare devono essere minori o uguali al numero degli storageSlots 
     * del DataBase da agregare - altrimenti verrà sollevata un eccezione in fase di creazione della DBStructure).
     * @param eachTime l'intervallo di tempo ogni quanto il DataBase da Aggregare deve essere aggregato.
     * @param aggregationFunction la Funzione che si occupa di aggregare i record del DataBase da aggregare.
     * @param storageSlots numero di slot di memorizzazione del database.
     */
    public DBAggregatedStructure(String DBname, String DBToAggregate, int slotsToAggregate, int eachTime,
    AggregationInterface aggregationFunction, int storageSlots ){
    	this.DBname = DBname;
    	this.DBToAggregate = DBToAggregate;
    	this.slotsToAggregate = slotsToAggregate;
    	this.eachTime = eachTime;
    	this.aggregationFunction = 	aggregationFunction;   
    	this.storageSlots = storageSlots;
    }
    
    /**
     * Restituisce il nome del DataBase Aggregato.
     * @return il nome del DataBase Aggregato.
     */
    public String getDBname(){
    	return DBname;
    }
    
     /**
     * Restituisce il nome del DataBase da Aggregare.
     * @return il nome del DataBase da Aggregare.
     */
    public String getDBToAggregate(){
    	return DBToAggregate;
    }
    
    /**
     * Restituisce il numero di slots del DataBase da Aggregare che vanno aggregati.
     * @return il numero di slots del DataBase da Aggregare che vanno aggregati.
     */
    public int getSlotsToAggregate(){
    	return slotsToAggregate;
    }
    
    /**
     * Restituisce l'intervallo di tempo ogni quanto il DataBase da Aggregare deve essere aggregato.
     * @return l'intervallo di tempo ogni quanto il DataBase da Aggregare deve essere aggregato.
     */
    public int getEachTime(){
    	return eachTime;
    }
    
    /**
     * Restituisce a Funzione che si occupa di aggregare i record del DataBase da aggregare.
     * @return la Funzione che si occupa di aggregare i record del DataBase da aggregare.
     */
    public AggregationInterface getAggregationFunction(){
    	return aggregationFunction;
    }
    
    /**
     * Restituisce il nome della Funzione che si occupa di aggregare i record del DataBase da aggregare.
     * @return il nome della Funzione che si occupa di aggregare i record del DataBase da aggregare.
     */
    public String getAggregationFunctionName(){
    	return aggregationFunction.getClass().getCanonicalName();
    }
    
    /**
     * Restituisce il numero di slot di memorizzazione del database.
     * @return il numero di slot di memorizzazione del database.
     */
    public int getStorageSlots(){
    	return storageSlots;
    }
}