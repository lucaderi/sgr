import java.io.*;
import java.awt.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.Date;

import javax.servlet.*;
import javax.servlet.http.*;

import org.jfree.chart.*;
import org.jfree.chart.ChartUtilities;

import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.CategoryItemRenderer;
import org.jfree.data.category.DefaultCategoryDataset;

import org.jfree.data.time.Hour;
import org.jfree.data.time.Minute;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;


public class ChartServlet extends HttpServlet {

    static String server = "";
    static String dbuser = "";
    static String dbpass = "";


    public void doGet (HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {


	String start = req.getParameter("StartTime");
	String title = req.getParameter("Title");

        if (title==null){title="";}

        if (start==null){System.exit(0);}
        int filter = Integer.parseInt(start);
        if (filter==0) {System.exit(0);}

	DateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.MINUTE, -filter);
	String tstart = df.format(calendar.getTime());

	String sql;
	if(req.getParameter("client")!=null){
	    sql = "SELECT timestamp AS hours, SUM(bytes)AS KBytes from pages WHERE client ='"+req.getParameter("client")+"' AND timestamp>='"+tstart+"' GROUP BY 1 ORDER BY 1";
	} else if (req.getParameter("server")!=null){
	    sql = "SELECT timestamp AS hours, SUM(bytes)AS KBytes from pages WHERE server ='"+req.getParameter("server")+"' AND timestamp>='"+tstart+"' GROUP BY 1 ORDER BY 1";
	} else {
	    sql = "SELECT timestamp AS hours, SUM(bytes)AS KBytes from pages WHERE timestamp>='"+tstart+"' GROUP BY 1 ORDER BY 1";
	}

	try {
	    Class.forName("org.postgresql.Driver");
	    Connection conn = DriverManager.getConnection("jdbc:postgresql:"+server, dbuser,dbpass);
	    if (conn == null) {
		System.exit(0);
	    }

	    ResultSetMetaData rsmd;
	    Statement st = conn.createStatement();
	    ResultSet rs = st.executeQuery(sql);
	    rsmd = rs.getMetaData();

	    TimeSeries series = new TimeSeries("bytes per second", Second.class);
	    Hour hour = new Hour();
	    Minute minute = new Minute();

	    while(rs.next()){

		String hours=rs.getString(1).split(" ")[1];
		int min=Integer.parseInt(hours.split(":")[1]);
		int sec=Integer.parseInt(hours.split(":")[2]);
            	series.add(new Second(sec, new Minute(min, new Hour(new Date(rs.getString(1))))) , rs.getLong(2)/1024);
	    }

            TimeSeriesCollection dataset = new TimeSeriesCollection(series);

	    JFreeChart chart = creaTSChart(dataset, title, "", rsmd.getColumnName(2));

	    OutputStream out = res.getOutputStream();
	    res.setContentType("image/png");
	    ChartUtilities.writeChartAsPNG(out, chart, 436, 230);

	} catch (Exception e) { }
    }

    public static JFreeChart creaTSChart(TimeSeriesCollection dataset, String title, String x, String y){

	JFreeChart chart = ChartFactory.createTimeSeriesChart(title, x, y, dataset, true, true, false );
	chart.getTitle().setPaint(Color.black);
	chart.setBackgroundPaint(Color.lightGray);
	chart.removeLegend();

	return chart;
    }
}
