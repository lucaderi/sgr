package analyzer;

import java.util.Vector;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Quando viene caricata la Servlet ne viene inizializzato
 * il Contesto.. 
 * Inizializzo nel contesto un Vettore contenete tutti i threads
 * 	che recuperano e analizano i pacchetti necessari.
 * 
 * @author Domenico Sulas
 */

public class ServletListener implements ServletContextListener {
	// vettore contenente tutti i thread in esecuzione
	private Vector<DownloadFiles> thr;
	
	
    /**
     * Default constructor. 
     */
    public ServletListener() {
    	thr= new Vector<DownloadFiles>();
    }

	/**
     * @see ServletContextListener#contextInitialized(ServletContextEvent)
     * 
     * inizializzo il vettore che contiene tutti i thread avviati dalla WebApp 
     */
    public void contextInitialized(ServletContextEvent arg0) {
    	ServletContext application = arg0.getServletContext();
    	
    	application.setAttribute( "threads", thr);
    }

	/**
     * @see ServletContextListener#contextDestroyed(ServletContextEvent)
     * 
     * fermo tutti i thread avviati dalla WebApp
     */
    public void contextDestroyed(ServletContextEvent arg0) {
    	for( int i= 0; i < thr.size(); i++)
			thr.elementAt( i).interrupt();
    }
	
}