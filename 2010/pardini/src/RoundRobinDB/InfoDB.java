package RoundRobinDB;

class InfoDB implements java.io.Serializable{
	private long lastTimeInsert;
	private long startTime;
	private int storageSlotNextInsert;
	private boolean flagInsert;
	private int storageSlots;
	private boolean firstTimeInsert = true;
	
    protected InfoDB(int storageSlots) {
    	this.storageSlotNextInsert = 0;
    	this.storageSlots = storageSlots;
    }
    
    protected long getLastTimeInsert(){
    	return lastTimeInsert;
    }
    
    protected void setLastTimeInsert(long lastTimeInsert){
    	this.lastTimeInsert=lastTimeInsert;
    } 
    
    protected int getStorageSlotNextInsert(){
    	return storageSlotNextInsert;
    }
    
    protected void setStorageSlotNextInsert(){
    	storageSlotNextInsert = storageSlotNextInsert + 1;
    	if(storageSlotNextInsert >=  storageSlots) storageSlotNextInsert = 0;
    }  
    
    protected boolean getFlagInsert(){
    	return flagInsert;
    }
    
    protected void setFlagInsert(boolean flagInsert){
    	this.flagInsert=flagInsert;
    }
    
    protected long getStartTime(){
    	return startTime;
    }
    
    protected void setStartTime(long startTime){
    	this.startTime=startTime;
    }
    
    protected boolean getfirstTimeInsert(){
    	return firstTimeInsert;
    }
    
    protected void setFirstTimeInsert(boolean firstTimeInsert){
    	this.firstTimeInsert=firstTimeInsert;
    }
}