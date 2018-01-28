package analyzer;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;





/**
 * Servlet che smista le richieste ricevute, alla pagina .jsp corretta
 * 
 * @author Domenico Sulas
 */

public class Analyzer extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	// pathfile dell applicazione
	private static final String dataPath= "webapps/AnalyzerBgp/";
	
	// vettore contenente tutti i thread in esecuzione
	private Vector<DownloadFiles> thr;
	
	// classe che gestisce il File dei repository noti
	private Repository repNoti;
	
	// la sessione della servlet
	private HttpSession session;
	
	// il dispatcher  delle richieste
	private RequestDispatcher dispatcher;
	
	
	/* Costruttore */
   
    public Analyzer() {
        super();
    }

    
    
    /* metodi pubblici */
	
	/**
	 * inizializza i threads necessari
	 */
    @SuppressWarnings("unchecked")
	public void init(){
    	
    	ServletContext contesto= this.getServletContext();
    	thr= (Vector<DownloadFiles>) contesto.getAttribute( "threads");
    	
    	repNoti= new Repository();
    	
    	if( thr.size()!= 0)
    		// il vettore e' gia stato inizializzato
    		return;
		
		String r= repNoti.load();
			
		if( r.equals( "") || r.equals( " "))
			// in una sessione precedente son stati cancellati tutti i repository!
			return;
		
			
		String[] rep= r.split( " ");
						
		for( int i= 0; i< rep.length; i++ ){
			// creo un nuovo thread per ogni repository noto! 
			DownloadFiles daemon= new DownloadFiles( rep[i], new NextHopInfo(), new OriginInfo(), new AutonomSystem() );			
			thr.add( daemon);

			try{
				daemon.start();					
			} catch( IllegalArgumentException e){
				String msgExc= e.getMessage();
					
				/* 	
				 * Il thread t viene interrotto solo se l'eccezzione catturata rende impossibile
				 *  comunicare col repository o reperire i file
				 */
				if( msgExc.contains( "Malformed URL") || msgExc.contains("Response")){						
					thr.remove( daemon);
					repNoti.clear( daemon.getUrl());
					
					String[] dir= daemon.getUrl().split( "/");
					clearAll( dir[ dir.length -1]);
					
					daemon.interrupt();
				}
					
				// reindirizzo sulla pagina d'errore
				session.setAttribute( "desc", msgExc);
				dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
				
				try {
					dispatcher.forward( null, null);
				} catch ( Exception e1) { e1.printStackTrace();}
			}
		}
    }
    
	/**
	 * metodo per la gestione delle richieste  GET
	 */
	protected void doGet( HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		String dir= request.getParameter( "dir"); // ottengo nome thread richiesto e la directory di lavoro
		
		// parametro no valido! reindirizzo alla pagina di benvenuto
		if( dir== null){
			// non ho ottenuto dei parametri..
			
			// setto come ”Moved Temporarily”  
		    // e faccio un redirect sula pagina di benvenuto
			response.setStatus( 302);
			response.setContentType( "text/html");
				
			response.sendRedirect(response.encodeRedirectURL( "./Data/welcome.jsp"));
		}
		else
			redirect( dir, dispatcher, request, response);			
		
	}

   
	
	/**
	 * metodo per la gestione dei POST
	 */
	protected void doPost( HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
				
		// ottengo la sessione e ci salvo l'ogetto per gestire i repository
		session= request.getSession( true);
		session.setAttribute( "repNoti", repNoti);
		
		// parametri ricevuti
		Enumeration<?> paramNames = request.getParameterNames();
		
		RequestDispatcher dispatcher= null;
		
		if( !paramNames.hasMoreElements()) {
			// non ho ottenuto paramentri.. visualizzo una pagina di errore! 
			
			session.setAttribute( "desc", "(Internal Error) No parameters entered");
			dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
		}
		else {
			// ho ottenuto parametri
			
			String paramName = (String) paramNames.nextElement();
			String val;
			
			if( paramName.equals( "nuovo")){				// richiesta inserimento nuovo repository				
				val= request.getParameter( "nuovo");
								
				// controllo se il repository e' gia in uso
				if( thr.contains( ( new DownloadFiles( val))) ){
					
					// SI! faccio una redirect sulla pagina che se ne occupa
					String[] dir= val.split( "/");
					redirect( dir[ dir.length -1], dispatcher, request, response);
					return;
				}				
				
				// controllo se l'url esiste
				HttpClient httpclient = new DefaultHttpClient();
				HttpGet httpget = new HttpGet( val);
				HttpResponse risp= null;
				
				try{
					risp = httpclient.execute( httpget);
				}catch( Exception e){					
					session.setAttribute( "desc", "Malformed URL: "+val);
					dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
					dispatcher.forward( request, response);
					return;
				}
				
				int status= risp.getStatusLine().getStatusCode();
				
				// controllo lo stato
				if( 200 <= status && status < 300){
					// ok il sito e' contattabile
										
					DownloadFiles daemon= new DownloadFiles( val, new NextHopInfo(), new OriginInfo(), new AutonomSystem() );
					thr.add( daemon);
					
					try{
						daemon.start();
						repNoti.add( daemon.getUrl());
					} catch( IllegalArgumentException e){
						String msgExc= e.getMessage();
						
						/* 	Il thread t viene interrotto solo se l'eccezzione catturata rende impossibile
						 *  comunicare col repository o reperire i file*/
						if( msgExc.contains( "Malformed URL") || msgExc.contains("Response")){
							daemon.interrupt();
							thr.remove( daemon);
							repNoti.clear( daemon.getUrl());
						}
						
						session.setAttribute( "desc", msgExc);
						dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
						dispatcher.forward( request, response);
						
						return;
					}
					
					String[] dir= val.split( "/");
					
					// aggiungo gli attributi
					session.setAttribute( "origine", daemon.getOrigin().get());
					session.setAttribute( "nextH", daemon.getNextHop().getBest());
					session.setAttribute( "as", daemon.getAS().getBest());
					session.setAttribute( "dir", "Data/"+dir[ dir.length -1]);
					
					dispatcher= session.getServletContext().getRequestDispatcher( "/Data/index.jsp");
				}
				else {
					// url valida ma Malformed.. visualizzo una pagina di errore!
					session.setAttribute( "desc", "Response: "+status+" (bad staus  probably the subfolder does not exist!)");
					dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
				}
			}
			else if( paramName.equals( "noti")){
				// richiesta visualizzazione repository noto
				
				val= request.getParameter( "noti");
				boolean find= false;
				
				for( int i= 0; i<= thr.size() && find== false; i++){
					DownloadFiles daemon= thr.elementAt( i);
					
					if( daemon.getUrl().equals( val)){						
						// info da passare alla pagina jsp
						String[] dir= val.split( "/");
						
						// aggiungo gli attributi
						session.setAttribute( "origine", daemon.getOrigin().get());
						session.setAttribute( "nextH", daemon.getNextHop().getBest());
						session.setAttribute( "as", daemon.getAS().getBest());
						session.setAttribute( "dir", "Data/"+dir[ dir.length -1]);
						dispatcher= session.getServletContext().getRequestDispatcher( "/Data/index.jsp");
						find= true;
					}					
				}
				
				if( find== false){
					// non ho trovato il repository richiesto.. visualizzo una pagina di errore!
					session.setAttribute( "desc", "(Internal Error) The server received a POST for an unknown URL");
					dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
				}
				
			}
			else if( paramName.equals( "canc")){
				// richiesta di fine monitoraggio
				
				val= request.getParameter( "canc");				
				
				for( int i= 0; i<= thr.size(); i++){
					DownloadFiles daemon= thr.elementAt( i);
				
					if( daemon.getUrl().equals( val)){
						thr.remove( i);						
						repNoti.clear( daemon.getUrl());
						
						try{
							daemon.interrupt();
						}catch( Exception e){}
						
						// cancello tutti i file usati dal thread
						String[] dir= val.split( "/");
						clearAll( dir[ dir.length -1]);
						
						// setto come ”Moved Temporarily”  
					    // e faccio un redirect sula pagina di benvenuto
						response.setStatus( 302);
						response.setContentType( "text/html");
						
						response.sendRedirect( response.encodeRedirectURL( "./Data/welcome.jsp"));
						return;
					}
				}
				
				// non ho trovato il repository richiesto.. visualizzo una pagina di errore!
				session.setAttribute( "desc", "(Internal Error) The server received a POST for an unknown URL");
				dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
				
			}
			else {
				// parametro sconosciuto.. visualizzo una pagina di errore!
				session.setAttribute( "desc", "(Internal Error) Unknown request");
				dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
			}
			
		}
		// invio la risposta
		dispatcher.forward( request, response);
	}
	
	
	/* metodi privati */
	
	/**
	 * fa il redirect sulla pagina di visualizzazione dati
	 * 
	 * @param dir: la directory di lavoro del thrad
	 * @param dispatcher: il dispatcher con cui lafer il redirect
	 * @param request: richiesta ricevuta 
	 * @param response: risposta da inviare
	 * 
	 * @throws IOException: controllare javax.servlet.RequestDispatcher.forward(ServletRequest  arg0, ServletResponse  arg1)
	 * @throws ServletException: controllare javax.servlet.RequestDispatcher.forward(ServletRequest  arg0, ServletResponse  arg1) 
	 */
	private void redirect( String dir, RequestDispatcher dispatcher, HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException{
		DownloadFiles daemon= null;

		// cerco il thread richiesto
		int i= 0;
		while( i< thr.size()){				
			if( (daemon= thr.elementAt( i)).getUrl().endsWith( dir+"/"))				
				break;
			else
				i++;
		}
		
		// controllo se ho trovato il thread richiesto
		
		if( i== thr.size()){
			// non trovato! reindirizzo alla pagina di errore..
			response.setStatus( 404); //?
			response.setContentType( "text/html");
			
			session.setAttribute( "desc", "(Internal Error) The server received a GET for an unknown URL");
			dispatcher= session.getServletContext().getRequestDispatcher( "/Data/error.jsp");
		}
		else{				
			// trovato! reindirizzo
			
			response.setStatus( 200);
			response.setContentType( "text/html");
			
			// Nota: passo il thread alla pagina jsp, che lo usera' per ricavare le informazioni da visualizzare
			session.setAttribute( "origine", daemon.getOrigin().get());
			session.setAttribute( "nextH", daemon.getNextHop().getBest());
			session.setAttribute( "as", daemon.getAS().getBest());
			session.setAttribute( "dir", "Data/"+dir);
			dispatcher= session.getServletContext().getRequestDispatcher( "/Data/index.jsp");
		}
		
		// invio la risposta
		dispatcher.forward(request,response);
		
	}

	
	
	/**
	 * cancella tutto il contenuto di una directory, e la directory stessa
	 * 
	 * @param d directori da cancellare 
	 */
	private void clearAll( String d){		
		File dir= new File( dataPath + "Data/"+ d);
						
		String[] contenuto= dir.list();
		
		for( int i= 0; i< contenuto.length; i++)
			(new File( dataPath + "Data/"+ d + "/" + contenuto[i])).delete();
				
		dir.delete();
		(new File( dataPath + "Downloads/" + d)).delete();
	}
	
}
