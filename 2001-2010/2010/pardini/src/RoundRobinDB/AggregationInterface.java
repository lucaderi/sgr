package RoundRobinDB;

public interface AggregationInterface extends java.io.Serializable{	
	/**
     * restituisce una matrice di oggetti le cui righe rappresentano i record aggregati.
     * (la matrice deve avere colonne == numberOfAttributesPerRecord e righe == maxRecordForTimeStep 
     * - se la matrice non rispetta tali dimensioni in fase di aggregazione verrà ignorata
     * e verra scritto sul DB aggregato il valore null al posto di tale matrice).
     * @param records è una matrice le cui righe rappresentano i records da aggregare.
     * @param maxRecordForTimeStep indica il massimo numero di record inseribili nel DB per intervallo di tempo.
     * @param numberOfAttributesPerRecord indica il numero di attributi per ogni singolo record.
     * @return una matrice di oggetti le cui righe rappresentano i record aggregati. 
     */
	public Object[][] aggregate (Object[][] records, int maxRecordForTimeStep, int numberOfAttributesPerRecord);		
}