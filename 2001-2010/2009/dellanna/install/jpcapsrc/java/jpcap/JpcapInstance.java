package jpcap;

abstract class JpcapInstance {
	protected static final int MAX_NUMBER_OF_INSTANCE = 255;

	protected static boolean[] instanciatedFlag = new boolean[MAX_NUMBER_OF_INSTANCE];

	protected int ID;

	protected int reserveID(){
		ID = -1;
		for (int i = 0; i < MAX_NUMBER_OF_INSTANCE; i++)
			if (!instanciatedFlag[i]) {
				ID = i;
				instanciatedFlag[i] = true;
				break;
			}
		return ID;
	}
	
	protected void unreserveID(){
		instanciatedFlag[ID]=false;
	}
}
