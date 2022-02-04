import java.io.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.Date;
import javax.servlet.*;
import javax.servlet.http.*;


public class HostDetails extends HttpServlet {

    static String server = "";
    static String dbuser = "";
    static String dbpass = "";

    public void doGet (HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
	res.setContentType("text/plain");
	PrintWriter out = res.getWriter();
	String p = req.getParameter("client");
	String p1 = req.getParameter("StartTime");

        if (p==null || p1 ==null){out.println("Invalid Request."); System.exit(0);}
        int filter = Integer.parseInt(p1);
        if (filter==0) {out.println("Invalid Request."); System.exit(0);}
        else {
	    DateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm");
    	    Date date = new Date();
    	    Calendar calendar = Calendar.getInstance();
    	    calendar.setTime(date);
    	    calendar.add(Calendar.MINUTE, -filter);

	    String sql = "SELECT server, SUM(bytes) AS nbytes, SUM(time) AS time, AVG(slatency) AS slatency FROM pages WHERE client='"+p+"' AND timestamp>'"+df.format(calendar.getTime())+"'GROUP BY 1 ORDER BY 2 DESC";

	    try{

    		Class.forName("org.postgresql.Driver");
		Connection conn = DriverManager.getConnection("jdbc:postgresql:"+server, dbuser,dbpass);
		if (conn == null) {
		    System.out.println("Failed to make connection to DB!");
		    System.exit(0);
		}

		Statement st = conn.createStatement();
		ResultSet rs = st.executeQuery(sql);

		out.println("<table border=\"10px\">"+
			"<tr><td width=\"275px\" align=\"center\"><b>Server</td>"+
			"<td width=\"75px\" align=\"center\"><b>Data Received</td>"+
			"<td width=\"75px\" align=\"center\"><b>FTime</td>"+
			"<td width=\"75px\" align=\"center\"><b>Latency(ms)</td>"+
			"<td width=\"5px\" align=\"center\"></td></tr></table>");

		out.println("<div style=\"width:536px; height:100px; overflow-y:scroll;\">");
		out.println("<table border=\"10px\">");

		while(rs.next()){
		    out.println("<tr><td width=\"275px\"><A HREF=\"index.jsp?mod=sdetails&server="+rs.getString("server")+"&StartTime="+req.getParameter("StartTime")+"\">"+rs.getString("server")+"</A>"+
				"</td><td width=\"75px\" align=\"center\">"+trasformBytes(rs.getLong("nbytes"))+
				"</td><td width=\"75px\" align=\"center\">"+trasformTime(rs.getDouble("time"))+"</td>"+
				"</td><td width=\"75px\" align=\"center\">"+String.format("%.3g%n",rs.getDouble("slatency"))+"</td></tr>");
		}
		out.println("</table></div>");

	     }catch (Exception e){System.out.println(e);}
	}
    }


    public String trasformTime(double d){
        int sec = (int)d;

        if(sec<60)
            return sec+" sec";
        else
            return sec/60+" min";
    }

    public String trasformBytes(long bytes){

        if(bytes<1024)
            return bytes+" b";
        else if (bytes<1048576)
            return bytes/1024+" kb";
        else return bytes/1048576+" Mb";
    }

}
