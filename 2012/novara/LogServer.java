import java.io.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.Date;

public class LogServer implements Runnable {

    static String dbserver = "";
    static String dbuser = "";
    static String dbpass = "";

    static Connection conn;

    String basedir = "/tmp/nprobe/";

    int hours = 3;

    String[] currentList;
    String[] toRead;

    String currentDir;
    Date start;


    public void run() {

	boolean init = true;

    	FileInputStream fstream;
        DataInputStream in;
        BufferedReader br;

    	Hashtable cache;
    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd/HH");
    	DateFormat dateFormat2 = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	Calendar cal = Calendar.getInstance();

    	while (true){
            try {
            	Date date = new Date();
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(date);
		calendar.add(Calendar.MINUTE, -1);
            	currentDir = dateFormat.format(calendar.getTime());
                calendar.add(Calendar.HOUR_OF_DAY, -hours);
                start = calendar.getTime();

            	File d1 = new File(basedir+currentDir);
            	if (d1.exists() && d1.isDirectory()){
                    if (currentList==null){//Prima esecuzione
                    	currentList = setPrefix(d1.list(),currentDir);
			for (int i = 0; i < hours; i++){
			    calendar.add(Calendar.HOUR_OF_DAY, i);
                   	    String tempDir = dateFormat.format( calendar.getTime() );
			    calendar.add(Calendar.HOUR_OF_DAY, -i);
                    	    File d2 = new File(basedir+tempDir);
                    	    if (d2.exists() && d2.isDirectory()){
                    		currentList = concatenate(currentList,setPrefix(d2.list(),tempDir));
                    	    }
			}
                    	Arrays.sort(currentList);
                        toRead=currentList;

                    }else {
                    	LinkedList<String> l1 = new LinkedList<String> ();
                        LinkedList<String> l2 = new LinkedList<String> ();
                        Collections.addAll (l1, setPrefix(d1.list(),currentDir));
                        Collections.addAll (l2, currentList);
                        l1.removeAll(l2);
                        currentList = setPrefix(d1.list(),currentDir);
                        Arrays.sort(currentList);
                        toRead = l1.toArray (new String[l1.size()]);
                    }


            	} else {
                    System.out.println("BaseDir does not exist");
                }

		int store=0;
            	if(toRead!=null){
		    for (String file : toRead){
			if(init) System.out.print(".");
            		if(file.split("\\.").length==2){
           		    File f = new File(basedir+file);
            		    if( (new Date(f.lastModified())).after(start) ){
  			        cache = new Hashtable();
				fstream = new FileInputStream(basedir+file);
				in = new DataInputStream(fstream);
				br = new BufferedReader(new InputStreamReader(in));
				String readedLine;
				String[] line;

				Statement st1 = conn.createStatement();

				for (int i = 0; i < 3; i++) { br.readLine(); }
				while ((readedLine = br.readLine()) != null)   {

				    line = readedLine.split("\t");
				    double time = Double.parseDouble(line[12])-Double.parseDouble(line[11]);
				    long times = Long.parseLong(line[11].replace(".",""));
                		    cal.setTimeInMillis(times);
				    st1.executeUpdate("INSERT INTO pages (timestamp, client, server, flowid, bytes, time, slatency) VALUES "+
						"('"+dateFormat2.format(cal.getTime())+"','"+line[0]+"','"+line[1]+"','"+line[13]+
						"','"+new Integer(line[10])+"','"+String.format("%.3g%n",time)+"','"+
						String.format("%.3g%n",Double.parseDouble(line[18]))+"')");

				}
				in.close();
            		    }
			}
            	    }
            	}

		Statement st2 = conn.createStatement();
		st2.executeUpdate("DELETE FROM pages WHERE timestamp < '"+dateFormat2.format(start)+"'");

		if(init) { System.out.println("\nInitialization completed, waiting for new nprobe dumps."); init=false; }
    		Thread.sleep(20000);

    	    } catch (Exception e) {
		System.out.println(e);
    	    }
  	}
    }

   public static void storeDB(Connection conn, Page p) throws Exception {
   }


    public static String[] concatenate(String[] a, String[] b){
    	String[] c = new String[a.length+b.length];
    	int i=0;
    	for(String s:a){
    		c[i]=s;
    		i++;
    	}
    	for(String s:b){
    		c[i]=s;
    		i++;
    	}
    	return c;
    }

    public static String[] setPrefix(String[] f, String p){
    	String[] r = new String[f.length];
    	int i=0;
    	for(String s:f){
    		r[i]=p+"/"+s;
    		i++;
    	}
    	return r;
    }


    public static void main(String[] args) throws Exception {
	try {
	    System.out.print("Initializing LogServer");
	    Class.forName("org.postgresql.Driver");
	    conn = DriverManager.getConnection("jdbc:postgresql:"+dbserver, dbuser,dbpass);
	    if (conn == null) {
		System.out.println("Failed to make connection to DB!");
		System.exit(0);
	    }
	    Statement st = conn.createStatement();
	    st.executeUpdate("DROP TABLE IF EXISTS pages");
	    st.executeUpdate("CREATE TABLE pages (timestamp varchar(20), client varchar(15), server varchar(100), flowid varchar(30), bytes int, time float (1), slatency float(1))");
	    Thread th = new Thread(new LogServer());
	    th.start();
	}catch (Exception e){System.out.println(e);}
    }

}
