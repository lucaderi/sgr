import java.io.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.Date;
import javax.servlet.*;
import javax.servlet.http.*;


public class HostsAnalysis extends HttpServlet {

    static String server = "";
    static String dbuser = "";
    static String dbpass = "";

    public void doGet (HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
	res.setContentType("text/plain");
	PrintWriter out = res.getWriter();
	String p = req.getParameter("StartTime");

	if (p==null){out.println("Invalid Request."); System.exit(0);}
	int filter = Integer.parseInt(p);
	if (filter==0) {out.println("Invalid Request."); System.exit(0);}

	else {
	    DateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm");
    	    Date date = new Date();
    	    Calendar calendar = Calendar.getInstance();
    	    calendar.setTime(date);
    	    calendar.add(Calendar.MINUTE, -filter);
	    String sql = "SELECT client, SUM(bytes) AS nbytes, SUM(time) AS time FROM pages WHERE timestamp>'"+df.format(calendar.getTime())+"'GROUP BY 1 ORDER BY 2 DESC";

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
			"<tr><td width=\"275px\" align=\"center\"><b>Host</td>"+
			"<td width=\"75px\" align=\"center\"><b>Data Received</td>"+
			"<td width=\"75px\" align=\"center\"><b>FTime</td>"+
			"<td width=\"75px\" align=\"center\"><b>Flows</td>"+
			"<td width=\"5px\" align=\"center\"> </td></tr></table>");


		out.println("<div style=\"width:536px; height:100px; overflow-y:scroll;\">");
		out.println("<table border=\"10px\">");

		while(rs.next()){

		    String sql1 ="SELECT count(*) AS flows FROM (SELECT flowid, count(*) FROM pages WHERE client='"+rs.getString("client")+"' "+
				"AND timestamp >'"+df.format(calendar.getTime())+"' GROUP BY 1) AS g;";

		    Statement st2 = conn.createStatement();
		    ResultSet rs2 = st2.executeQuery(sql1);
		    int flows = 0;
		    if(rs2.next()) {flows=rs2.getInt("flows"); }

		    out.println("<tr><td width=\"275px\"><A HREF=\"index.jsp?mod=hdetails&client="+rs.getString("client")+"&StartTime="+p+"\">"+rs.getString("client")+
				"</td><td width=\"75px\" align=\"center\">"+trasformBytes(rs.getLong("nbytes"))+
				"</td><td width=\"75px\" align=\"center\">"+trasformTime(rs.getDouble("time"))+"</td>"+
				"</td><td width=\"75px\" align=\"center\">"+flows+"</td></tr>");

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
