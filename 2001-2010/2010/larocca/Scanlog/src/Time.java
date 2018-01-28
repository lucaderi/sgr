/**
 * Class Time
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class Time {
	private int BeginTime;
	private int EndTime;

	/**
	 * Costruttore
	 */
	public Time() {
		this.BeginTime = 0;
		this.EndTime = 0;
	}

	/**
	 * Funzione di aggiornamento del BeginTime
	 * 
	 * @param BeginTime
	 */
	public void updateBeginTime(int BeginTime) {
		this.BeginTime = BeginTime;
	}

	/**
	 * Funzione di aggiornamento dell'EndTime
	 * 
	 * @param EndTime
	 */
	public void updateEndTime(int EndTime) {
		this.EndTime = EndTime;
	}

	/**
	 * Metodo che ritorna il BeginTime
	 * 
	 * @return BeginTime
	 */
	public int getBeginTime() {
		return this.BeginTime;
	}

	/**
	 * Metodo che ritorna l'EndTime
	 * 
	 * @return EndTime
	 */
	public int getEndTime() {
		return this.EndTime;
	}

	/**
	 * Metodo che ritorna il tempo totale di navigazione
	 * 
	 * @return tempo totale di navigazione del client
	 */
	public int getTotalTime() {
		return this.EndTime - this.BeginTime;
	}
}
