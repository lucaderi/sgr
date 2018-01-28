import java.util.Vector;

public class ExampleAggregationFunction implements RoundRobinDB.AggregationInterface{
	private class elem implements java.io.Serializable{
		public Object[] record = null;
		public int count = 1;
		
		public elem(Object[] record){
			this.record=record;
		}
		
		public boolean equals(Object obj){
			String A = (String) record[0];
			elem tmp = (elem) obj;
			String B = (String) tmp.record[0];;
			return A.equals(B);
		}
	}
	    
    public Object[][] aggregate (Object[][] records, int maxRecordForTimeStep, int numberOfAttributesPerRecord){
    	Vector<elem> vettore = new Vector<elem>();
    	
    	for(int i = 0; i < records.length; i++){
    		if(records[i][0] != null && records[i][1] != null){
	    		elem elemTmp = new elem(records[i]);
	    		int index = vettore.indexOf(elemTmp,0);
	    		if(index == -1) vettore.add(elemTmp);
	    		else{
	    			elemTmp = vettore.get(index);
	    			elemTmp.count = elemTmp.count + 1;
	    			for(int j = 1; j < numberOfAttributesPerRecord; j++){
	    				int a = Integer.parseInt((String) elemTmp.record[j]);
		    			int b = Integer.parseInt((String) records[i][j]);
		    			elemTmp.record[j] = "" + (a + b);
	    			}
	    		}
    		}
    	}
    	
    	Object[][] tmp = new Object[maxRecordForTimeStep][numberOfAttributesPerRecord];
    	int insElem = 0;
    	boolean flagStop = false;
    	
    	while(insElem<maxRecordForTimeStep && !flagStop){
    		int tmpCount = 0;
    		int index = 0;
    		if(vettore.size() > 0){
    			for(int i = 0; i < vettore.size(); i++){
	    			elem tmpElem = vettore.get(i);
	    			if(tmpCount < tmpElem.count){
	    				index = i;
	    				tmpCount = tmpElem.count;
	    			}
	    			if(tmpCount == tmpElem.count){
	    				int flag = index;
	    				elem tmpElemIndex = vettore.get(index);
	    				for(int j = 1; (j < numberOfAttributesPerRecord && flag == index); j++){
	    					int a = Integer.parseInt((String) tmpElemIndex.record[j]);
		    				int b = Integer.parseInt((String) tmpElem.record[j]);
	    					if(a < b){
	    						index = i;
	    					}
	    				}
	    			}
	    		}
	    		tmp[insElem] = vettore.remove(index).record;
    		}else{
    			flagStop = true;			        
    		}
    		insElem = insElem + 1;     	   		
    	}    	 
    	return tmp;
    }
}