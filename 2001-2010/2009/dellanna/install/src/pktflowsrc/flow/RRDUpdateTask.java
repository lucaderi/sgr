/**
 * 
 */
package flow;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.TimerTask;

/**
 * Questa classe rappresenta il task che viene eseguito nel momento in cui si vuole effettuare un update dei dati riguardanti i flussi spirati in un RRD
 * 
 * @author dellanna
 *
 */
final class RRDUpdateTask extends TimerTask {

	private final Collector collector;//riferimento al collector da cui raccogliere i dati riguardanti i flussi
	private final Runtime runtime;//riferimento al runtime della JVM in esecuzione corrente
	private final static String[] UPDATERRDCMD={"rrdtool", "update", "", "--template=flows", ""}; //comando per l'update di un dato all'interno di un rrd
	private final String rrd;//riferimento all'rrd
	private final static String[] UPDATEGRAPHHOURCMD={"rrdtool", "graph", "", "--start", "end-1h", "--vertical-label", "flow/sec", "--title", "FLOWS PER HOUR", "--lower-limit", "0", "","LINE2:flows#0000ff:'flow speed'"};//comando per l'update del grafico dei flussi per ora relativo un rrd
	private final String graph_hour;//riferimento al file png relativo il grafico dei flussi per ora di un rrd
	private final static String[] UPDATEGRAPHDAYCMD={"rrdtool", "graph", "", "--vertical-label", "flow/sec", "--title", "FLOWS PER DAY", "--lower-limit", "0", "", "LINE2:flows#0000ff:'flow speed'"};//comando per l'update del grafico dei flussi per giorno relativo un rrd
	private final String graph_day;//riferimento al file png relativo il grafico dei flussi per giorno di un rrd
	
	
	//collector: riferimento al collector da cui recuperare il contatore dei flussi spirati
	//rrd: riferimento all'rrd su cui vengono effettuati gli updates. Se non esiste RRDUpdateTask lo crea.
	//graph_hour: riferimento al grafico dei flussi per ora
	//graph_day: riferimento al grafico dei flussi per giorno
	RRDUpdateTask(Collector collector,String rrd,String graph_hour,String graph_day) throws Exception{
		this.collector = collector;
		this.runtime=Runtime.getRuntime();
		this.rrd=rrd;
		this.graph_hour=graph_hour;
		this.graph_day=graph_day;
		//se non esiste crea l'RRD
		File rrdfile=new File(this.rrd);
		if(!rrdfile.exists()){
			System.out.println(this.rrd+" doesn't exist! creating...");
			String[] cmd={"rrdtool","create",this.rrd,"--start","now","--step","60","DS:flows:COUNTER:119:0:U","RRA:LAST:0:1:60","RRA:AVERAGE:0.5:5:288"};
			Process proc=runtime.exec(cmd);
			proc.waitFor();
		}else
			System.out.println("Flow datas saved on "+this.rrd);
		System.out.println("Flow per hour graph saved on "+this.graph_hour);
		System.out.println("Flow per day graph saved on "+this.graph_day);
		
		//esegue il primo aggiornamento inizializzando il contatore dei flussi a 0
		UPDATERRDCMD[2]=this.rrd;
		UPDATERRDCMD[4]="N:0";
		Process proc=runtime.exec(UPDATERRDCMD);
		proc.waitFor();
		//disegna il grafico aggiornato dei flussi per ora
		UPDATEGRAPHHOURCMD[2]=this.graph_hour;
		UPDATEGRAPHHOURCMD[11]="DEF:flows="+this.rrd+":flows:LAST"; 
		proc=runtime.exec(UPDATEGRAPHHOURCMD);
		proc.waitFor();
		//disegna il grafico aggiornato dei flussi per giorno
		UPDATEGRAPHDAYCMD[2]=this.graph_day;
		UPDATEGRAPHDAYCMD[9]="DEF:flows="+this.rrd+":flows:AVERAGE"; 
		proc=runtime.exec(UPDATEGRAPHDAYCMD);
		proc.waitFor();
	}

	
	//corpo del thread
	public void run() {
		//recupera i dati relativi il contatore di flussi dal collector
		int counter=this.collector.getCounter();
		//esegue l'aggiornamento
		try {
			UPDATERRDCMD[2]=this.rrd;
			UPDATERRDCMD[4]="N:"+counter;
			Process proc=runtime.exec(UPDATERRDCMD);
			proc.waitFor();
			//disegna il grafico aggiornato dei flussi per ora
			UPDATEGRAPHHOURCMD[2]=this.graph_hour;
			UPDATEGRAPHHOURCMD[11]="DEF:flows="+this.rrd+":flows:LAST"; 
			proc=runtime.exec(UPDATEGRAPHHOURCMD);
			proc.waitFor();
			//disegna il grafico aggiornato dei flussi per giorno
			UPDATEGRAPHDAYCMD[2]=this.graph_day;
			UPDATEGRAPHDAYCMD[9]="DEF:flows="+this.rrd+":flows:AVERAGE"; 
			proc=runtime.exec(UPDATEGRAPHDAYCMD);
			proc.waitFor();
		} catch (Exception e) {
			System.err.println(e+" Update failed!");
		} 
	}

}
