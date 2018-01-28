import RoundRobinDB.*;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class RoundRobinDBTool{
	private static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));	
	public static void main(String[] args){
		System.out.println("");
		RoundRobinDB RRD = null;
		DBStructure dbStructure = null;
		RecordAttribute[] RS = null;
		DBAggregatedStructure[] DBASs = null;
		while(true){
			System.out.print("RRD> ");
			String tmp = "";
			boolean flagCommand = false;
			try{tmp = reader.readLine();
			}catch(IOException e){}
			String[] comandi = tmp.split(" ");
		
			if(comandi[0].equalsIgnoreCase("CREATE")){
				flagCommand = true;
				if(RRD == null){
					try{
						System.out.println("");
						System.out.println("<RoundRobinDB>");
						System.out.print("DBname: ");
						String DBname = reader.readLine();
						int timeStep = readInt("timeStep");
						int timeTollerance = readInt("timeTollerance");
						while(timeStep <= timeTollerance){
							System.out.println("ERRORE: timeTollerance deve essere < di timeStep");
							timeTollerance = readInt("timeTollerance");
						}
						int stroageSlots = readInt("stroageSlots");
						
						System.out.println("");
						int numberDBAggregati = readIntB("Qunti DB Aggregati vuoi???(0 per nessuno)");
						if(numberDBAggregati > 0){
							DBASs = new DBAggregatedStructure[numberDBAggregati];
							for(int i = 0; i < numberDBAggregati; i++){
								System.out.println("");	
			    				System.out.println("<DB Aggregated>");
			    				System.out.print("DBname: ");
								String DBAggregateName = reader.readLine();
								System.out.print("DBtoAggregate: ");
								String DBToAggregate = reader.readLine();
								int slotsToAggregate = readInt("slotsToAggregate");
								int eachTime = readInt("eachTime");
								AggregationInterface aggregationFunction = null;
								while(aggregationFunction == null){
									System.out.print("aggregationFunction: ");
							    	try{
							    		aggregationFunction = (AggregationInterface) Class.forName(reader.readLine()).newInstance();
							    	}catch(Exception e){System.out.println("ERRORE: Funzione di Aggregazione non valida");}
								}							
								int DBAggregateStorageSlots = readInt("storageSlots");
								DBASs[i] = new DBAggregatedStructure(DBAggregateName,DBToAggregate,slotsToAggregate,eachTime,aggregationFunction,DBAggregateStorageSlots);
							}
						}
						
						System.out.println("");	
				    	System.out.println("<Record Structure>");
	    				int maxRecordForTimeStep = readInt("maxRecordForTimeStep");
	    				
						int numberOfAttributesPerRecord = readIntB("Quanti attributi vuoi che abbia ogni record???");
						while(numberOfAttributesPerRecord < 1){
							System.out.println("ERRORE: numberOfAttributesPerRecord deve essere >= 1");
							numberOfAttributesPerRecord = readIntB("Quanti attributi vuoi che abbia ogni record???");
						}
						RS = new RecordAttribute[numberOfAttributesPerRecord];
						for(int i = 0; i < numberOfAttributesPerRecord; i++){
							System.out.print("attributeName: ");
							String attributeName = reader.readLine();
							int maxByteLength = readInt("maxByteLength");
							RS[i] = new RecordAttribute(attributeName,maxByteLength);
						}
						
						if(numberDBAggregati > 0) dbStructure = new DBStructure(DBname,timeStep,timeTollerance,stroageSlots,DBASs,maxRecordForTimeStep,RS);
						else dbStructure = new DBStructure(DBname,timeStep,timeTollerance,stroageSlots,maxRecordForTimeStep,RS);
						
						RRD = new RoundRobinDB(dbStructure);
	    				System.out.println("");
					}catch(IllegalArgumentException e){System.out.println("ERRORE: hai inserito alcuni paramatri non validi - per chiarificazioni vedi le API");}
					catch(IOException e){System.out.println("ERRORE: I/O Exception in creazione dell'RRD");return;}
				}else System.out.println("ERRORE: hai già aperto o creato un RoundRobinDB");
			}
			
			if(comandi[0].equalsIgnoreCase("OPEN")){
				if(comandi.length == 2){
					flagCommand = true;
					if(RRD == null){
						try{
							RRD = new RoundRobinDB(comandi[1]);
							dbStructure = RRD.info();
							RS = dbStructure.getRecordStructure();
							DBASs = dbStructure.getDBASs();
						}catch(IllegalArgumentException e){System.out.println("ERRORE: non esiste alcun RRD col nome specificato");}
						catch(IOException e){System.out.println("ERRORE: I/O Exception in apertura dell'RRD"); return;}					
					}else System.out.println("ERRORE: hai già aperto o creato un RoundRobinDB");
				}
			}
			
			if(comandi[0].equalsIgnoreCase("INSERT")){
				flagCommand = true;
				if(RRD != null){
					Object[][] records = new Object[dbStructure.getMaxRecordForTimeStep()][dbStructure.getNumberOfAttributesPerRecord()];
					int i = 0;
					boolean flagStop = false;
					System.out.println("");
					while(i < dbStructure.getMaxRecordForTimeStep() && !flagStop){
						for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){
							System.out.print(RS[j].getAttributeName()+": ");
							try{
								tmp = reader.readLine();
							}catch(IOException e){}
							records[i][j] = tmp;
						}
						i = i + 1;
						if(i < dbStructure.getMaxRecordForTimeStep()){
							boolean flag = true;
							while(flag){
								System.out.print("Vuoi inserire un altro record???(Y per YES/N per NO): ");
								try{
									tmp = reader.readLine();
									if(tmp.equalsIgnoreCase("Y")){flag = false;}
									if(tmp.equalsIgnoreCase("N")){flag = false; flagStop = true;}
								}catch(IOException e){}
							}
						}
					}
					try{
						RRD.insert(records);
					}catch(IOException e){}
					System.out.println("");
				}else System.out.println("ERRORE: non hai ancora aperto o creato un RoundRobinDB");
			}
			
			if(comandi[0].equalsIgnoreCase("SELECT")){
				boolean flagInt = true;
				if(comandi.length == 3){
					flagCommand = true;
					int LastXSlots = 0;
					try{
						LastXSlots = Integer.parseInt(comandi[2]);
						if(LastXSlots <= 0) {
							System.out.println("ERRORE: il parametro LastXSlots deve essere un numero intero > di 0");
							flagInt = false;
						}
					}catch(NumberFormatException e){
						System.out.println("ERRORE: il parametro LastXSlots deve essere un numero intero > di 0");
						flagInt = false;
					}
					if(flagInt == true){
						if(RRD != null){
							try{
								Object[][] select = RRD.select(comandi[1],LastXSlots);
								System.out.println("");
								System.out.println("Last "+LastXSlots+" slot of DB "+comandi[1]+":");					    						    	
						    	for(int i = 0; i < select.length; i++){
						    		if(i%dbStructure.getMaxRecordForTimeStep()==0)
						    			System.out.println("---------------------------------------");
						    		for(int j = 0; j < select[i].length; j++){
						    			System.out.print(RS[j].getAttributeName()+": "+(String) select[i][j]+" ");
						    		}
						    		System.out.println("");
						    	}
						    	System.out.println("---------------------------------------");
						    	System.out.println("");	
							}catch(IllegalArgumentException e){System.out.println("ERRORE: il DB specificato non esiste");}
							catch(IOException e){System.out.println("ERRORE: I/O Exception in SELECT");}							
						}else System.out.println("ERRORE: non hai ancora aperto o creato un RoundRobinDB");
					}					
				}
			}
			
			if(comandi[0].equalsIgnoreCase("INFO")){
				flagCommand = true;
				if(RRD != null){
					System.out.println("");
					System.out.println("<RoundRobinDB>");
					System.out.println("DBname: "+dbStructure.getDBname());
			    	System.out.println("timeStep: "+dbStructure.getTimeStep());
			    	System.out.println("timeTollerance: "+dbStructure.getTimeTollerance());
			    	System.out.println("stroageSlots: "+dbStructure.getStorageSlots());
			    	if(DBASs != null){
			    		for(int i = 0; i < DBASs.length; i++){
			    			System.out.println("");	
			    			System.out.println("<DB Aggregated>");
					    	System.out.println("DBname: "+DBASs[i].getDBname());
					    	System.out.println("DBtoAggregate: "+DBASs[i].getDBToAggregate());
					    	System.out.println("slotsToAggregate: "+DBASs[i].getSlotsToAggregate());
					    	System.out.println("eachTime: "+DBASs[i].getEachTime());
					    	System.out.println("aggregationFunction: "+DBASs[i].getAggregationFunctionName());
					    	System.out.println("storageSlots: "+DBASs[i].getStorageSlots());
			    		}
			    	}
			    	System.out.println("");	
			    	System.out.println("<Record Structure>");
    				System.out.println("maxRecordForTimeStep: "+dbStructure.getMaxRecordForTimeStep());
			    	for(int i = 0; i < RS.length; i++){
			    		System.out.println("attributeName: "+RS[i].getAttributeName());
    					System.out.println("maxByteLength: "+RS[i].getMaxByteLength());
			    	}
					System.out.println("");	
				}else System.out.println("ERRORE: non hai ancora aperto o creato un RoundRobinDB");
			}
						
			if(comandi[0].equalsIgnoreCase("RESET")){
				flagCommand = true;
				if(RRD != null){
					try{RRD.reset();
					}catch(IOException e){System.out.println("ERRORE: I/O Exception in reset dell'RRD"); return;}	
				}else System.out.println("ERRORE: non hai ancora aperto o creato un RoundRobinDB");
			}
			
			if(comandi[0].equalsIgnoreCase("QUIT")){
				flagCommand = true;
				if(RRD != null){
					try{RRD.close();
					}catch(IOException e){System.out.println("ERRORE: I/O Exception in chiusura dell'RRD"); return;}				
					return;	
				}else return;
			}
			
			if(flagCommand == false){
				System.out.println("ERRORE: comando non valido");
			}
		}
	}
	
	private static int readInt(String msg) throws IOException{
		boolean flagInt = true;
		int result = 0;
		while(flagInt){
			System.out.print(msg+": ");
			try{
				result = Integer.parseInt(reader.readLine());
				if(result <= 0) {
					System.out.println("ERRORE: il parametro "+msg+" deve essere un numero intero > di 0");
				}else flagInt = false;
			}catch(NumberFormatException e){
				System.out.println("ERRORE: il parametro "+msg+" deve essere un numero intero > di 0");
			}
		}
		return result;		
	}
	
	private static int readIntB(String msg) throws IOException{
		boolean flagInt = true;
		int result = 0;
		while(flagInt){
			System.out.print(msg+": ");
			try{
				result = Integer.parseInt(reader.readLine());
				flagInt = false;
			}catch(NumberFormatException e){
				System.out.println("ERRORE: il parametro deve essere un numero intero");
			}
		}
		return result;		
	}
}		