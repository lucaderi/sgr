/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import java.util.ArrayList;
import java.util.Collection;
import java.util.TreeMap;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

/**
 *
 * @author ricardopinto
 */
public class CaptureManager {

    /**
     * atributes
     */
    private TreeMap<String,Capturer> tmap_capturers = new TreeMap<String,Capturer>();
    private DataWorker dw = new DataWorker();

    /**
     * Singleton mehthods
     * 
     */
    /*private static class SingletonHolder {
	private static final CaptureManager INSTANCE = new CaptureManager();
    }*/

    public CaptureManager(){
        init();
    }

    /*public static CaptureManager getSingleton(){
	return SingletonHolder.INSTANCE;
    }*/


    /**
     * public interface
     */

    public void init(){

        this.tmap_capturers.clear();
        ArrayList<String> i_names = new ArrayList<String>();

        int i = 0;
        for( NetworkInterface ni : JpcapCaptor.getDeviceList() ){
            Capturer c = new LiveCapturer( ni );
            c.setDataSource(i++);
            this.tmap_capturers.put(c.getCapturerName(), c);
            i_names.add(c.getCapturerName());
        }

        i--;

       String[] int_names = new String[i_names.size()];

        for( i=0 ; i<i_names.size() ; i++ ){
            int_names[i] = i_names.get(i);
        }

        DataCollector.getSingleton().setDataSources(int_names);
    }

    public Collection<String> getInterfaceList(){
        ArrayList<String> list = new ArrayList<String>();

        for( Capturer c : this.tmap_capturers.values() )
            list.add(c.getCapturerName());

        return list;
    }

    public void startCapturer( String ni ){
        Capturer c = tmap_capturers.get(ni);

        if( c!=null && !c.isRunning() ){
            c.start();
            dw.start();
        }
    }

    public void stopCapturer( String ni ){
        Capturer c = tmap_capturers.get(ni);

        if( c!=null ){
            //System.out.println("Stoping sniffer!!"+ni);
            c.stop();
            dw.stop();
        }

        //if( DataCollector.getSingleton().hasChanged() ) DataCollector.getSingleton().notifyObservers();
    }

    /*public void startAllCapturers(){
        //DataCollector.getSingleton().clear();
        for( String c : tmap_capturers.keySet() ) startCapturer(c);
    }*/

    public void stopAllCapturers(){
	for( String c : tmap_capturers.keySet() ) stopCapturer(c);

        //if( DataCollector.getSingleton().hasChanged() ) DataCollector.getSingleton().notifyObservers();
    }

    public Capturer getInterface(String net_i) {
        return this.tmap_capturers.get(net_i);
    }

    public void setInterfaceOptions(String net_i, boolean promiscuous, boolean filter_active, String filter) {
        LiveCapturer c = (LiveCapturer)this.tmap_capturers.get(net_i);

        if( c==null ) return;

        c.setPromiscuous(promiscuous);
        c.setFilterActive(filter_active);
        c.setFilter(filter);
    }


    //inner class for data parsing (independent thread that works as long as there's any capture running)
    private class DataWorker implements Runnable{

        private Thread t = null;
        private boolean running = false;
        private Integer capturers_working = 0;

        public DataWorker(){}

        public void start(){
            ++capturers_working;
            if(!running){
                //System.out.println("DataWorker working!!");
                DataCollector.getSingleton().clear();
                running = true;
                t = new Thread(this);
                t.start();
            }
            //System.out.println("starter-caps_w:"+capturers_working);
        }

        public void stop(){
            --capturers_working;
            if( capturers_working<=0 ){
                //System.out.println("DataWorker stoping!!");
                running = false;
            }
            //System.out.println("stoper-caps_w:"+capturers_working);
        }

        public void run() {
            while(running){
                DataCollector.getSingleton().parsePackets();
                //System.out.println("DataWorker has parsed data!!");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    System.out.println("InterruptEx: "+ex.getMessage());
                }
            }
            
            DataCollector.getSingleton().parsePackets();
            if( DataCollector.getSingleton().hasChanged() ) DataCollector.getSingleton().notifyObservers();
        }

    }
    


}
