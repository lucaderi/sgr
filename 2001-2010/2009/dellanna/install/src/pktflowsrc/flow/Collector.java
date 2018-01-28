/**
 * 
 */
package flow;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;

/**
 * Questa classe realizza un Thread Collector che prende tutti i flussi inviati dai worker e li salva in una pagina html autoaggiornante o li stampa a video.
 * 
 * @author dellanna
 *
 */
final class Collector extends Thread {

	private final FlowQueue[] flow_queue; //coda di flussi inviati al Collector
	private boolean choice; // a seconda della scelta il collector stampa a video i flussi o li scrive nel last.xml che sara' letto da pktflow.html 
	private final static File FLOWS=new File("./pktflowgui/flows/flows.xml");//riferimento al file xml in cui sono salvati i file xml piu' recenti
	private RandomAccessFile flows; //riferimento al file cui accedere tramite RandomAccessFile
	private int counter; //contatore di flussi ricevuti
	
	//flow_queue: array di code flussi associate al Collector
	//chioce: a seconda della scelta i flussi vengono stampati a video o salvati nel file flows.xml
	Collector(FlowQueue[] flow_queue,boolean choice) {
		this.flow_queue = flow_queue;
		this.counter=0;
		this.choice=choice;
		if(choice){
			System.out.println("Flows saved in ./pktflowgui/flows/flows.xml. You can see them starting ./pktflowgui/pktflow.html web page.");
			//se il file non esiste viene creato
			this.flows=null;
			try {
				//soluzione "senza memoria" 
				if(FLOWS.exists())
					FLOWS.delete();
				FLOWS.createNewFile();
				//genera il file xml iniziale lo codifica in UTF-8 e lo scrive in flows.xml
				String flow="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<?xml-stylesheet type=\"text/xsl\" href=\"tabletemplate.xsl\"?>\n<fs>\n</fs>";
				String utf8_flow=new String(flow.getBytes(),"UTF-8");
				FileOutputStream fout=new FileOutputStream(FLOWS);
				fout.write(utf8_flow.getBytes());
				fout.flush();
				fout.close();
				//accesso al file
				this.flows=new RandomAccessFile(FLOWS,"rw");
			} catch (IOException e) {
				System.err.println(e+" Operation failed! Redirecting flows on stdout...");
				this.choice=false;
			}//fine blocco try/catch
		}else{
			System.out.println("Flows will be printed on stdout");
		}
	}


	//corpo del thread
	public void run() {
		boolean flag;
		Flow flow;
		while(true){
			flag=true;
			while(flag){
				flag=false;
				for(int i=0;i<flow_queue.length;i++)
					if((flow=(flow_queue[i].removeFirst()))!=null){
						flag=true;
						//aggiorna contatore
						this.counter++;
						if(this.choice){//stampa su file
							try {
								this.flows.seek(this.flows.length()-5);
								this.flows.write((flow.getXml(this.counter)+"</fs>").getBytes("UTF-8"));
							} catch (IOException e) {
								System.err.println(e+" Operation failed! Redirecting flows on stdout...");
								this.choice=false;
							}
						}else{//stampa a video
							System.out.println("THREAD: "+(i+1));
							System.out.println(flow);
						}
					}
			}//fine while
			//se non ci sono piu' flussi da stampare a video il thread va in attesa attiva
			Thread.yield();
		}//fine while
	}//fine run
	
	
	//ritorna il contatore dei flussi "spirati"
	int getCounter(){
		return this.counter;
	}
}