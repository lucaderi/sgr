package RoundRobinDB;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.StreamCorruptedException;

public class RoundRobinDB{
	private DBStructure dbStructure;
	private boolean firstTimeInsert = true;
	private RandomAccessFile DB = null;
	private RandomAccessFile[] DBAggregated = null;
	private InfoDB infoDB = null;
	private InfoDB[] infoDBAggregated = null;
	private boolean flagInsert = true;
	private Thread threadTimerTimeStep;
	private Thread threadTollerance;
	private Thread[] threadDBAggregations;
	
	/**
     * Costruttore della Classe RoundRobinDB.
     * Da utilizzare per creare un nuovo RRD.
     * @param dbStructor è un oggetto che rappresenta la struttura dell'RRD che si vuole creare.
     */	
	public RoundRobinDB(DBStructure dbStructure) throws IOException{
		this.dbStructure = dbStructure;
		File file = new File(dbStructure.getDBname());
    	if(file.isFile() == false && file.isDirectory() == false) file.mkdir();
    	file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".rrd");
    	DB = new RandomAccessFile(file,"rw");
    	DB.setLength(dbStructure.getSeekStep()*dbStructure.getStorageSlots());
    	this.infoDB = new InfoDB(dbStructure.getStorageSlots());
    	
    	DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		if(DBASs != null){
			this.DBAggregated = new RandomAccessFile[DBASs.length];
			this.infoDBAggregated = new InfoDB[DBASs.length];
			this.threadDBAggregations = new Thread[DBASs.length];
			
			for(int i = 0; i < DBASs.length; i++){
				file = new File(dbStructure.getDBname(),DBASs[i].getDBname()+".rrd");
		    	DBAggregated[i] = new RandomAccessFile(file,"rw");
		    	DBAggregated[i].setLength(dbStructure.getSeekStep()*DBASs[i].getStorageSlots());
		    	this.infoDBAggregated[i] = new InfoDB(DBASs[i].getStorageSlots());
			}				
		}    	
	}
	
	/**
     * Costruttore della Classe RoundRobinDB.
     * Da utilizzare per aprire un RRD già esistente.
     * @param DBname è il nome di un RRD già esistente.
     * @exception IllegalArgumentException se l'RRD specificato non esiste.
     * @exception IOException se si è verificato un errore in lettura della struttara dell'RRD.
     */	
	public RoundRobinDB(String DBname) throws IllegalArgumentException, IOException{
		File file = new File(DBname);
		if(file.isDirectory() == false) throw new IllegalArgumentException( );
		file = new File(file,DBname+".RRDstr");
		if(file.isFile() == false) throw new IllegalArgumentException( );		
	
		FileInputStream fis = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(fis);
        try{this.dbStructure = (DBStructure) ois.readObject();
        }catch (ClassNotFoundException e){throw new IOException( );}        
		ois.close();
		
    	file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".rrd");
    	DB = new RandomAccessFile(file,"rw");
    	
    	file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".infoDB");
    	fis = new FileInputStream(file);
        ois = new ObjectInputStream(fis);
        try{this.infoDB = (InfoDB) ois.readObject();
        }catch (ClassNotFoundException e){throw new IOException( );}
        this.infoDB.setFirstTimeInsert(true);       
		ois.close();
    	
    	DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		if(DBASs != null){			
			this.DBAggregated = new RandomAccessFile[DBASs.length];
			this.infoDBAggregated = new InfoDB[DBASs.length];
			this.threadDBAggregations = new Thread[DBASs.length];
			
			for(int i = 0; i < DBASs.length; i++){
				file = new File(dbStructure.getDBname(),DBASs[i].getDBname()+".rrd");
		    	DBAggregated[i] = new RandomAccessFile(file,"rw");
		    	
		    	file = new File(dbStructure.getDBname(),DBASs[i].getDBname()+".infoDB");
		    	fis = new FileInputStream(file);
		        ois = new ObjectInputStream(fis);
		        try{this.infoDBAggregated[i] = (InfoDB) ois.readObject();
		        }catch (ClassNotFoundException e){throw new IOException( );} 
		        this.infoDBAggregated[i].setFirstTimeInsert(true);          
				ois.close();
			}				
		}    	  	
	}
	
	/**
     * inserisce i records passati nel RRD.
     * @param records è una matrice di oggetti le cui righe rappresentano i record da inserire nel DB.
     * (gli oggetti contenuti in questa matrice devono tutti implementare Serializable - altrimenti nel caso in cui 
     * uno o più oggetti non implementino Serializable al loro posto verrà scritto NULL).
     * (la matrice deve avere colonne == dbStructure.getNumberOfAttributesPerRecord()
     * e righe <= dbStructure.getMaxRecordForTimeStep() - altrimenti viene sollevata un eccezione).
     * (ogni attributo di ogni record deve inoltre essere di dimensione minore o uguale al maxByteLength
     * specificato per quell'attributo - altrimenti invece di tale attributo verrà scritto NULL).
     * @exception IllegalArgumentException se la matrice non rientra nelle dimensioni sopra specificate.
     * @exception IOException se si verifica una I/O exception.  
     */
	public void insert(Object [][] records) throws IllegalArgumentException, IOException{
		if(records.length > dbStructure.getMaxRecordForTimeStep()) throw new IllegalArgumentException( );
		for(int i = 0; i < records.length; i++){
			if(records[i].length != dbStructure.getNumberOfAttributesPerRecord()) throw new IllegalArgumentException( );
		} 
		
		if(firstTimeInsert) {
			insertFirstTime(records); 
			firstTimeInsert = false;		
		}else{
			long currentTime = System.currentTimeMillis();
			synchronized(infoDB){
				if(flagInsert != infoDB.getFlagInsert()){
					flagInsert = !flagInsert;
					insertIntoDB(records,false);					
					infoDB.setLastTimeInsert(currentTime);
					infoDB.setStorageSlotNextInsert();									
				}else{					
					if((currentTime - infoDB.getLastTimeInsert())/1000 < dbStructure.getTimeStep()){
						insertIntoDB(records,false);
						infoDB.setLastTimeInsert(currentTime);
					}else{
						insertIntoDB(records,true);
						infoDB.setLastTimeInsert(currentTime);	
						infoDB.setStorageSlotNextInsert();
						infoDB.setStorageSlotNextInsert();	
					}										
				}
			}
		}
	}
	
	private void insertFirstTime(Object [][] records) throws IOException{		
		insertIntoDB(records,false);
		
		long currentTime = System.currentTimeMillis();
		infoDB.setLastTimeInsert(currentTime);
		infoDB.setStartTime(currentTime);
		infoDB.setFlagInsert(true);
		infoDB.setFirstTimeInsert(false);
		infoDB.setStorageSlotNextInsert();
		
		threadTimerTimeStep = new ThreadTimerTimeStep(infoDB, dbStructure.getTimeStep());
		threadTimerTimeStep.setDaemon(true);
		threadTimerTimeStep.setPriority(10);
		threadTimerTimeStep.start();
		threadTollerance = new ThreadTollerance(infoDB, dbStructure.getTimeStep(), dbStructure.getTimeTollerance(), DB, 
		dbStructure.getMaxRecordForTimeStep() ,dbStructure.getRecordStructure(), dbStructure.getSeekStep());
		threadTollerance.setDaemon(true);
		threadTollerance.setPriority(10);
		threadTollerance.start();
		
		DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		if(DBASs != null){
			for(int i = 0; i < DBASs.length; i++){
				infoDBAggregated[i].setStartTime(currentTime);
				infoDBAggregated[i].setFirstTimeInsert(true);
				InfoDB tmpInfoDBToAggregate = null;
				int tmpTimeStepDBToAggregate = 0;
				RandomAccessFile tmpDBToAggregate = null;
				boolean flagDBToAggregateIsMainDB = true;
				if((dbStructure.getDBname()).equals(DBASs[i].getDBToAggregate())){
					tmpInfoDBToAggregate = infoDB;
					tmpDBToAggregate = DB;
					tmpTimeStepDBToAggregate = dbStructure.getTimeStep();
				}else{
					int j = 0;
					while(flagDBToAggregateIsMainDB==true){
						if((DBASs[j].getDBname()).equals(DBASs[i].getDBToAggregate()) && j!=i){
							tmpInfoDBToAggregate = infoDBAggregated[j];
							tmpDBToAggregate = DBAggregated[j];
							tmpTimeStepDBToAggregate = DBASs[j].getEachTime();
							flagDBToAggregateIsMainDB = false;
						}
						j = j + 1;
					}
				}
				threadDBAggregations[i] = new ThreadDBAggregation(infoDBAggregated[i], DBAggregated[i], 
					tmpInfoDBToAggregate, tmpDBToAggregate, DBASs[i], tmpTimeStepDBToAggregate,
					dbStructure, flagDBToAggregateIsMainDB);
				threadDBAggregations[i].setDaemon(true);
				threadDBAggregations[i].start();
			}				
		}    	  	
	}
	
	private void insertIntoDB(Object [][] records, boolean flagSpread) throws IOException{
		RecordAttribute[] RS = dbStructure.getRecordStructure();
		byte[] bufferWrite = null;
    	ByteArrayOutputStream baos = null;
		ObjectOutputStream oos  = null;
		
		byte[] objectNull = null;
		baos = new  ByteArrayOutputStream();
		oos = new ObjectOutputStream(baos);			
		oos.writeObject(null);	
		objectNull = baos.toByteArray();	
		
		long seek = dbStructure.getSeekStep() * infoDB.getStorageSlotNextInsert();
			
		for(int i = 0; i < records.length; i++){
			for(int j = 0; j < records[i].length; j++){
				if(records[i][j] instanceof java.io.Serializable){
					baos = new  ByteArrayOutputStream();
					oos = new ObjectOutputStream(baos);			
					oos.writeObject(records[i][j]);	
					bufferWrite = baos.toByteArray();
					
					if((bufferWrite.length - 4) <= RS[j].getMaxByteLength()){
						DB.seek(seek);//
						DB.write(bufferWrite);
						if(flagSpread){
							DB.seek(seek+dbStructure.getSeekStep());//
							DB.write(bufferWrite);	
						}	
					}else{
						DB.seek(seek);//
						DB.write(objectNull);
						if(flagSpread){
							DB.seek(seek+dbStructure.getSeekStep());//
							DB.write(objectNull);	
						}		
					}
				}else{
					DB.seek(seek);//
					DB.write(objectNull);
					if(flagSpread){
						DB.seek(seek+dbStructure.getSeekStep());//
						DB.write(objectNull);	
					}		
				}
				seek = seek + RS[j].getMaxByteLength() + 4;
			}
		}
		
		if(records.length < dbStructure.getMaxRecordForTimeStep()){
			for(int i = records.length; i < dbStructure.getMaxRecordForTimeStep(); i++){
				for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){
					DB.seek(seek);//
					DB.write(objectNull);
					if(flagSpread){
						DB.seek(seek+dbStructure.getSeekStep());//
						DB.write(objectNull);	
					}
					seek = seek + RS[j].getMaxByteLength() + 4;
				}		
			}
		}	
		return;
	}
	
	/**
     * restituisce i record del DataBase specificato.
     * @param DBname è il nome del DB da cui estrarre i valori.
     * @param getLastXSlots indica il numero di slots che vuoi a partire dall'ultimo inserito.
     * (se getLastXSlots è <= 0 viene sollevata un eccezione).
     * (se getLastXSlots è > di storageSlots del database specificato allora verranno restituiti tutti gli storageSlots).
     * @return una matrice di oggetti le cui righe rappresentano i record inseriti nel DB. 
     * @exception IllegalArgumentException se il DB specificato non esiste oppure getLastXSlots è <= 0.
     * @exception IOException se si verifica una I/O exception.  
     */
	public Object [][] select(String DBname, int getLastXSlots) throws IllegalArgumentException, IOException{
		if(getLastXSlots <= 0) throw new IllegalArgumentException( );
		if(DBname.equals(dbStructure.getDBname())) return selectFromDB(getLastXSlots);
		else{
			DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
			if(DBASs != null){
				for(int i = 0; i < DBASs.length; i++){
					if(DBname.equals(DBASs[i].getDBname())) return selectFromDBAggregated(getLastXSlots,i);
				}				
			}
			throw new IllegalArgumentException( );						
		}
	}
	
	private Object [][] selectFromDB(int getLastXSlots) throws IOException{
		int LastXSlots = getLastXSlots;
		if(getLastXSlots > dbStructure.getStorageSlots()) LastXSlots = dbStructure.getStorageSlots();
		Object[][] records = new Object[dbStructure.getMaxRecordForTimeStep()*LastXSlots][dbStructure.getNumberOfAttributesPerRecord()];
		
		byte[] bufferRead = new byte[dbStructure.getMaxByteLengthBetweenAllRecordAttributes()];
		ByteArrayInputStream bais = null;
		ObjectInputStream ois = null;
		
		RecordAttribute[] RS = dbStructure.getRecordStructure();
		
		synchronized(infoDB){
			int indexStorageSlot = infoDB.getStorageSlotNextInsert();
			if(infoDB.getfirstTimeInsert())	indexStorageSlot = indexStorageSlot - 1;				
			long seek = 0;			
			
			for(int z = 0; z < LastXSlots; z++){
				
				indexStorageSlot = indexStorageSlot - 1;
				if(indexStorageSlot < 0) indexStorageSlot = dbStructure.getStorageSlots() - 1;
				seek = dbStructure.getSeekStep() * indexStorageSlot;
				
				for(int i = (z*dbStructure.getMaxRecordForTimeStep()); i < ((z + 1)*dbStructure.getMaxRecordForTimeStep()); i++){
					for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){
						DB.seek(seek);//
						DB.read(bufferRead);		
						try{
							bais = new ByteArrayInputStream(bufferRead);
							ois = new ObjectInputStream(bais);
							records[i][j] = ois.readObject();
						}catch(StreamCorruptedException e){records[i][j] = null;}
						catch(ClassNotFoundException e){records[i][j] = null;}
						seek = seek + RS[j].getMaxByteLength() + 4;
					}
				}
			}
		}		
		return records;		
	}
	
	private Object [][] selectFromDBAggregated(int getLastXSlots, int indexInArrayDBAggregated) throws IOException{
		DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		int LastXSlots = getLastXSlots;
		if(getLastXSlots > DBASs[indexInArrayDBAggregated].getStorageSlots()) LastXSlots = DBASs[indexInArrayDBAggregated].getStorageSlots();
		Object[][] records = new Object[dbStructure.getMaxRecordForTimeStep()*LastXSlots][dbStructure.getNumberOfAttributesPerRecord()];
		byte[] bufferRead = new byte[dbStructure.getMaxByteLengthBetweenAllRecordAttributes()];
		ByteArrayInputStream bais = null;
		ObjectInputStream ois = null;
			
		RecordAttribute[] RS = dbStructure.getRecordStructure();
			
		synchronized(infoDBAggregated[indexInArrayDBAggregated]){			
			int indexStorageSlot = infoDBAggregated[indexInArrayDBAggregated].getStorageSlotNextInsert();
			if(infoDBAggregated[indexInArrayDBAggregated].getfirstTimeInsert())	indexStorageSlot = indexStorageSlot - 1;		
			long seek = 0;			
			
			for(int z = 0; z < LastXSlots; z++){
				
				indexStorageSlot = indexStorageSlot - 1;
				if(indexStorageSlot < 0) indexStorageSlot = DBASs[indexInArrayDBAggregated].getStorageSlots() - 1;
				seek = dbStructure.getSeekStep() * indexStorageSlot;
				
				for(int i = (z*dbStructure.getMaxRecordForTimeStep()); i < ((z + 1)*dbStructure.getMaxRecordForTimeStep()); i++){
					for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){
						DBAggregated[indexInArrayDBAggregated].seek(seek);//
						DBAggregated[indexInArrayDBAggregated].read(bufferRead);		
						try{
							bais = new ByteArrayInputStream(bufferRead);
							ois = new ObjectInputStream(bais);
							records[i][j] = ois.readObject();
						}catch(StreamCorruptedException e){records[i][j] = null;}
						catch(ClassNotFoundException e){records[i][j] = null;}
						seek = seek + RS[j].getMaxByteLength() + 4;
					}
				}
			}
		}		
		return records;	
	}
	
	/**
     * chiude i file costituenti l'RRD e termina tutti i thread che gestiscono l'RRD e che sono in esecuzione.
     * @exception IOException se si verifica una I/O exception.  
     */
	public void close() throws IOException{
		DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		
		if(threadTimerTimeStep != null){		
			threadTimerTimeStep.interrupt();
			try{threadTimerTimeStep.join();
			}catch(InterruptedException e){return;}
			
			threadTollerance.interrupt();
			try{threadTollerance.join();
			}catch(InterruptedException e){return;}			
			
			if(DBASs != null){
				for(int i = 0; i < DBASs.length; i++){
					threadDBAggregations[i].interrupt();
					try{threadDBAggregations[i].join();
					}catch(InterruptedException e){return;}
				}				
			}
		}
		
		File file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".RRDstr");	
		FileOutputStream fos = new FileOutputStream(file);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(dbStructure);   
		oos.close();
		
		DB.close();
		
		file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".infoDB");	
		fos = new FileOutputStream(file);
        oos = new ObjectOutputStream(fos);
        infoDB.setStorageSlotNextInsert();
        oos.writeObject(infoDB);   
		oos.close();
		
		if(DBASs != null){
			for(int i = 0; i < DBASs.length; i++){
				DBAggregated[i].close();
				
				file = new File(dbStructure.getDBname(),DBASs[i].getDBname()+".infoDB");	
				fos = new FileOutputStream(file);
		        oos = new ObjectOutputStream(fos);
		        infoDBAggregated[i].setStorageSlotNextInsert();
		        oos.writeObject(infoDBAggregated[i]);   
				oos.close();
			}				
		}		
		return;
	}
	
	/**
     * restituisce un oggetto di tipo DBStructure che rappresenta la struttura dell' RRD.
     * @return un oggetto di tipo DBStructure che rappresenta la struttura dell'RRD.  
     */
	public DBStructure info(){
		return dbStructure;	
	}
	
	/**
     * resetta i file costituenti l'RRD e termina tutti i thread che gestiscono l'RRD e che sono in esecuzione.
     * @exception IOException se si verifica una I/O exception.  
     */
	public void reset() throws IOException{
		DBAggregatedStructure[] DBASs = dbStructure.getDBASs();
		
		if(threadTimerTimeStep != null){		
			threadTimerTimeStep.interrupt();
			try{threadTimerTimeStep.join();
			}catch(InterruptedException e){return;}
			
			threadTollerance.interrupt();
			try{threadTollerance.join();
			}catch(InterruptedException e){return;}			
			
			if(DBASs != null){
				for(int i = 0; i < DBASs.length; i++){
					threadDBAggregations[i].interrupt();
					try{threadDBAggregations[i].join();
					}catch(InterruptedException e){return;}
				}				
			}
		}
		
		DB.close();
		File file = new File(dbStructure.getDBname(),dbStructure.getDBname()+".rrd");
		file.delete();
    	DB = new RandomAccessFile(file,"rw");
    	DB.setLength(dbStructure.getSeekStep()*dbStructure.getStorageSlots());
    	this.infoDB = new InfoDB(dbStructure.getStorageSlots());
    	
    	if(DBASs != null){			
			for(int i = 0; i < DBASs.length; i++){
				DBAggregated[i].close();
				file = new File(dbStructure.getDBname(),DBASs[i].getDBname()+".rrd");
				file.delete();
		    	DBAggregated[i] = new RandomAccessFile(file,"rw");
		    	DBAggregated[i].setLength(dbStructure.getSeekStep()*DBASs[i].getStorageSlots());
		    	this.infoDBAggregated[i] = new InfoDB(DBASs[i].getStorageSlots());
			}				
		}
		return;	
	}
		
	//ThreadTimerTimeStep
	private class ThreadTimerTimeStep extends Thread{
		private InfoDB infoDB;
		private int timeStep;
		private boolean flagInsert = true;
		
		protected ThreadTimerTimeStep(InfoDB infoDB, int timeStep){
			this.timeStep = timeStep;
			this.infoDB = infoDB;
		}
		
		public void run(){
			while(true){
				synchronized(infoDB){
					try{infoDB.wait(timeStep*1000);
					}catch(InterruptedException e){return;}
					
					long currentTime = System.currentTimeMillis();
					if((currentTime - infoDB.getLastTimeInsert())/1000 > timeStep) infoDB.notifyAll();					
					
					if(infoDB.getFlagInsert() == true) infoDB.setFlagInsert(false);
					else infoDB.setFlagInsert(true);
					flagInsert=infoDB.getFlagInsert();
				}
			}
		}
	}
	
	//ThreadTollerance
	private class ThreadTollerance extends Thread{
		private InfoDB infoDB;
		private int timeTollerance;
		private int timeStepAndTimeTollerance;
		private RandomAccessFile DB = null;
		private int maxRecordForTimeStep;
		private RecordAttribute[] RS = null;
		private long seekStep;
		
		protected ThreadTollerance(InfoDB infoDB, int timeStep, int timeTollerance, RandomAccessFile DB,
		int maxRecordForTimeStep, RecordAttribute[] RS, long seekStep){
			this.timeTollerance = timeTollerance;
			this.timeStepAndTimeTollerance = (timeStep+timeTollerance);
			this.infoDB = infoDB;
			this.DB = DB;
			this.maxRecordForTimeStep=maxRecordForTimeStep;
			this.RS=RS;
			this.seekStep=seekStep;
		}
		
		public void run(){
			while(true){
				synchronized(infoDB){
					try{infoDB.wait();
					}catch(InterruptedException e){return;}
					
					try{infoDB.wait(timeTollerance*1000);
					}catch(InterruptedException e){return;}
									
					if((System.currentTimeMillis()-infoDB.getLastTimeInsert())/1000 > timeStepAndTimeTollerance){
						if(infoDB.getFlagInsert() == true) infoDB.setFlagInsert(false);
						else infoDB.setFlagInsert(true);
						
						try{insertIntoDB();
						}catch(IOException e){System.out.println("ERRORE ThreadTollerance"); return;}
						
						infoDB.setStorageSlotNextInsert();					
					}
				}
			}
		}
		
		private void insertIntoDB() throws IOException{
			byte[] objectNull = null;
			ByteArrayOutputStream baos = new  ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);			
			oos.writeObject(null);	
			objectNull = baos.toByteArray();	
			
			long seek = seekStep * infoDB.getStorageSlotNextInsert();
				
			for(int i = 0; i < maxRecordForTimeStep; i++){
				for(int j = 0; j < RS.length; j++){				
					DB.seek(seek);//
					DB.write(objectNull);			
					seek = seek + RS[j].getMaxByteLength() + 4;
				}
			}	
			return;
		}
	}
	
	//ThreadDBAggregation
	private class ThreadDBAggregation extends Thread{
		private InfoDB infoDBToAggregate;
		private InfoDB infoDB;
		private RandomAccessFile DB = null;
		private RandomAccessFile DBToAggregate = null;
		private DBAggregatedStructure dbAggregatedStructure;
		private DBStructure dbStructure;
		private int timeStepDBToAggregate;
		private RecordAttribute[] RS = null;
		private boolean flagWait; 
		
		protected ThreadDBAggregation(InfoDB infoDB, RandomAccessFile DB,
		 	InfoDB infoDBToAggregate, RandomAccessFile DBToAggregate, 
		 	DBAggregatedStructure dbAggregatedStructure, int timeStepDBToAggregate,
		 	DBStructure dbStructure, boolean flagDBToAggregateIsMainDB){
			this.infoDB = infoDB;
			this.DB = DB;
			this.infoDBToAggregate = infoDBToAggregate;
			this.DBToAggregate = DBToAggregate;
			this.dbAggregatedStructure = dbAggregatedStructure;
			this.dbStructure = dbStructure;
			this.timeStepDBToAggregate = timeStepDBToAggregate;
			this.RS = dbStructure.getRecordStructure();
			this.flagWait = (!flagDBToAggregateIsMainDB) && (dbAggregatedStructure.getEachTime()%timeStepDBToAggregate == 0);
		}
		
		public void run(){
			Object[][] records = null;
			while(true){	
				synchronized(infoDBToAggregate){
					long startTime = System.currentTimeMillis()/1000;
					long sleepTime = dbAggregatedStructure.getEachTime();
					long currentTime = 0;
					while(sleepTime > 0){
						try{infoDBToAggregate.wait(sleepTime*1000);
						}catch(InterruptedException e){return;}
						currentTime = System.currentTimeMillis()/1000;
						sleepTime = dbAggregatedStructure.getEachTime()-(currentTime-startTime);					
					}
					if(flagWait){
						if((currentTime - infoDBToAggregate.getLastTimeInsert()) >= timeStepDBToAggregate){
							try{infoDBToAggregate.wait();
							}catch(InterruptedException e){return;}	
						}					
					}
						
					records = null;
					try{records = selectFromDBToAggregate();
					}catch(IOException e){}				
				}
				
				if(records != null)
				records = (dbAggregatedStructure.getAggregationFunction()).aggregate(records, dbStructure.getMaxRecordForTimeStep(), dbStructure.getNumberOfAttributesPerRecord());
				
				synchronized(infoDB){
					try{insertIntoDB(records);
					}catch(IOException e){System.out.println("Errore in scrittura DB: "+dbAggregatedStructure.getDBname()); return;}
					infoDB.setFirstTimeInsert(false);
					infoDB.setStorageSlotNextInsert();
					infoDB.setLastTimeInsert(System.currentTimeMillis()/1000);
					infoDB.notifyAll();	
				}
			}
		}
		
		private Object[][] selectFromDBToAggregate() throws IOException{
			byte[] bufferRead = new byte[dbStructure.getMaxByteLengthBetweenAllRecordAttributes()];
			ByteArrayInputStream bais = null;
			ObjectInputStream ois = null;
			
			int LastXSlots = dbAggregatedStructure.getSlotsToAggregate();
			long timeFromStart = (System.currentTimeMillis() - infoDBToAggregate.getStartTime())/1000;
			long storageSlotInsertIntoDBToAggregate = timeFromStart / timeStepDBToAggregate;
			if(storageSlotInsertIntoDBToAggregate < dbAggregatedStructure.getSlotsToAggregate()) 
				LastXSlots = (int) storageSlotInsertIntoDBToAggregate;
			
			Object[][] matrix = new Object[dbStructure.getMaxRecordForTimeStep()*LastXSlots][dbStructure.getNumberOfAttributesPerRecord()];
			
			int indexStorageSlot = infoDBToAggregate.getStorageSlotNextInsert();
			if(infoDBToAggregate.getfirstTimeInsert()) indexStorageSlot = indexStorageSlot - 1;				
			long seek = 0;			
			
			for(int z = 0; z < LastXSlots; z++){
				
				indexStorageSlot = indexStorageSlot - 1;
				if(indexStorageSlot < 0) indexStorageSlot = dbStructure.getStorageSlots() - 1;
				seek = dbStructure.getSeekStep() * indexStorageSlot;
				
				for(int i = (z*dbStructure.getMaxRecordForTimeStep()); i < ((z + 1)*dbStructure.getMaxRecordForTimeStep()); i++){
					for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){		
						try{
							DBToAggregate.seek(seek);//
							DBToAggregate.read(bufferRead);
							bais = new ByteArrayInputStream(bufferRead);
							ois = new ObjectInputStream(bais);
							matrix[i][j] = ois.readObject();
						}catch(StreamCorruptedException e){matrix[i][j] = null;}
						catch(ClassNotFoundException e){matrix[i][j] = null;}
						seek = seek + RS[j].getMaxByteLength() + 4;
					}
					}
			}
			return matrix;		
		}
		
		private void insertIntoDB(Object [][] records) throws IOException{
			boolean flagRecordRighe = true;
			boolean flagRecordColonne = true;
			if(records == null) flagRecordRighe = false;
			else if(records.length != dbStructure.getMaxRecordForTimeStep()) flagRecordRighe = false;
			
			byte[] bufferWrite = null;
	    	ByteArrayOutputStream baos = null;
			ObjectOutputStream oos  = null;
			
			byte[] objectNull = null;
			baos = new  ByteArrayOutputStream();
			oos = new ObjectOutputStream(baos);			
			oos.writeObject(null);	
			objectNull = baos.toByteArray();	
			
			long seek = dbStructure.getSeekStep() * infoDB.getStorageSlotNextInsert();
				
			for(int i = 0; i < dbStructure.getMaxRecordForTimeStep(); i++){
				flagRecordColonne = true;
				if(flagRecordRighe == true) if(records[i].length != dbStructure.getNumberOfAttributesPerRecord()) flagRecordColonne = false; 
				for(int j = 0; j < dbStructure.getNumberOfAttributesPerRecord(); j++){		
					if(flagRecordRighe == true && flagRecordColonne == true){
						baos = new  ByteArrayOutputStream();
						oos = new ObjectOutputStream(baos);			
						oos.writeObject(records[i][j]);	
						bufferWrite = baos.toByteArray();
						DB.seek(seek);//
						DB.write(bufferWrite);					
					}else{
						DB.seek(seek);//
						DB.write(objectNull);		
					}
					seek = seek + RS[j].getMaxByteLength() + 4;
				}
			}
			return;
		}
	}
}