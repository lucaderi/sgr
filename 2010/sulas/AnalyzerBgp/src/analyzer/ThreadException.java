package analyzer;


/**
 * 
 * classe che implementa un eccezzione sollevabile da un thread
 * 
 * @author Domenico Sulas
 */



public class ThreadException implements Thread.UncaughtExceptionHandler{

	@Override
	public void uncaughtException(Thread arg0, Throwable arg1) {
		System.out.println(arg0+" throw: "+arg1.getMessage());		
	}

}
