package reti;

import java.util.*;

public class ArgumentParser {
	
	private Hashtable<String, String> options = new Hashtable<String, String>();
	//Costruttore
	public ArgumentParser(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-")) {
				int loc = args[i].indexOf("=");
				boolean ok = false;
				String key;
				if(args[i].charAt(1) == '-'){
					if(args[i].indexOf('=')==-1){
						key = args[i].substring(2, args[i].length()); 
						if(key.compareTo("help") ==0){
							options.put(key.toLowerCase(), "");
						}else{
							System.out.println("Attenzione il parametro \"" + key + "\" non esiste quindi, verrà quindi ignorato");
						}
					}else{
						key = (loc > 0) ? args[i].substring(2, loc) : args[i].substring(1);
						ok= ControllaEsistenza((String) args[i].subSequence(2, args[i].indexOf('=')));
						if(!ok){
							System.out.println("Attenzione il parametro \"" + args[i].subSequence(2, args[i].indexOf('=')) + "\" non esiste quindi, verrà quindi ignorato");
						}
					}
				}else{
					if(args[i].indexOf('=')==-1){
						key = args[i].substring(1, args[i].length()); 
						if(key.compareTo("help") ==0){
							options.put(key.toLowerCase(), "");
						}else{
							System.out.println("Attenzione il parametro \"" + key + "\" non esiste quindi, verrà quindi ignorato");
						}
					}else{
						ok = ControllaEsistenza((String) args[i].subSequence(1, args[i].indexOf('=')));
						key = (loc > 0) ? args[i].substring(1, loc) : args[i].substring(1);
						if(!ok){
							System.out.println("Attenzione il parametro \"" + args[i].subSequence(1, args[i].indexOf('=')) + "\" non esiste quindi, verrà quindi ignorato");
						}
					}
				}
				String value = (loc > 0) ? args[i].substring(loc+1) : "";
				if(ok){
					options.put(key.toLowerCase(), value);
				}
			}
		}
	}
	//Controlla se la stringa passata come parametro � nella lista di quelle consentite
	private boolean ControllaEsistenza(String subSequence) {
		if(subSequence.compareTo("db") == 0 || subSequence.compareTo("log") == 0 || subSequence.compareTo("file") == 0 || subSequence.compareTo("protocols") == 0 || subSequence.compareTo("html") == 0 || subSequence.compareTo("start") == 0 || subSequence.compareTo("end") == 0 || subSequence.compareTo("help") == 0 ){
			return true;
		}
		return false;
	}
	//Ritorna true se la stringa passata come parametro fa parte delle opzioni passate
	public boolean hasOption(String opt) {
		return options.containsKey(opt.toLowerCase());
	}
	//Ritorna il valore della stringa passata come parametro
	public String getOption(String opt) {
		return (String) options.get(opt.toLowerCase());
	}

}