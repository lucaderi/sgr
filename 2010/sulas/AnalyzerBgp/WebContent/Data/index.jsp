<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ page language="java" contentType="text/html; charset=UTF-8"  pageEncoding="UTF-8"%>

<jsp:useBean id="repNoti" class="analyzer.Repository" scope="session"/>


<%!	String dir; %>
<%! String redir; %>
<%! String host;%>
<%  
	host = java.net.InetAddress.getLocalHost().getHostAddress();
	dir= (String) session.getAttribute( "dir");
	if( dir.contains( "/")){
		String[] t= dir.split( "/");
		redir= t[ t.length -1];
	}
	else
		redir= dir;
	
%>


<html>
	<head>
		<%
  			response.setHeader( "Pragma", "no-cache" );
   			response.setHeader( "Cache-Control", "no-cache" );
   			response.setDateHeader( "Expires", 0 );   			
		%>		
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<%-- la pagina vien refreshata ogni 5 minuti --%>		
		<meta http-equiv="Refresh" content="300 ; url=http://<% out.print( host);%>:8080/AnalyzerBgp/Analyzer?dir=<%  out.print( redir);%>">
    	<title>Analyzer BGP</title>
	</head>

<body link="#0000FF" vlink="#800080">
	
	<center>
		<h1 style=" color: #660099;"><u>Analyzer BGP</u></h1>
		<h5> <% out.println( "(this page is updated every 5 minutes)");%> </h5>
		<br />		
		<br />
		<h3> <% out.println( "Status of repository <u style=' color: #006600;'>" +redir+ "</u> at: "+( new java.util.Date()).toString()); %> </h3>
        <br />
        <%
		out.println( "<sub>All averages refer to the last 4 hours, others values refer to the last 10 minutes </sub><br/><br />");
        	out.println( "<br/><img src='"+dir+"/pac.png'"+"alt='Create image...' longdesc='pac.png' width='497' height='316' />");
        	out.println( "<br /><br /><sub> (Details) </sub><br /><br />");
        	out.println( "<img src='"+dir+"/req.png'"+"alt='Create image...' longdesc='req.png' width='497' height='288' />");
        	out.println( "<img src='"+dir+"/oth.png'"+"alt='Create image...' longdesc='oth.png' width='497' height='330' />");
        	out.println( "<br /><br />");        	
        	
        	
        	int[] origini= { 0, 0, 0};
        	origini= (int[])session.getAttribute( "origine");
        				
			int totale= origini[0] + origini[1] + origini[2];
			
			if( totale== 0)
				totale= 1;
			
			float percentuale;
			
			out.println( "<table align=center border=0>");
			out.println( "<tr valign='top' align='left'><td><b>Latest source packages</b></td></tr>");
			percentuale= (float) origini[0]/totale*100;
			out.println( "<tr><td>IGP <img src='./Data/barraBlu.png' width="+percentuale*5+" height=12></td><td align='right'>"+percentuale+"%</td></tr>");
			percentuale= (float) origini[1]/totale*100;
			out.println( "<tr><td>EGP <img src='./Data/barraRossa.png' width="+percentuale*5+" height=12></td><td align='right'>"+percentuale+"%</td></tr>");
			percentuale= (float) origini[2]/totale*100;
			out.println( "<tr><td>INC <img src='./Data/barraVerde.png' width="+percentuale*5+" height=12></td><td align='right'>"+percentuale+"%</td></tr>");
			out.println( "</table>");
    		out.println( "<br />");
        %>
        <br />
        
	
	<br />
	<br />
	<br />
	
	
	<h3> Historical Information </h3>
	<sub>All averages and values refer to the last week </sub><br /><br />
	<table width="90%" >
		<tr>
		<td width="70%">
			<%
				out.println( "<br />");
				out.println( "<img src='"+dir+"/sto.png'"+"alt='Create image...' longdesc='sto.png' width='697' height='202' />");
			%>			
		</td>

		<td width="30%">
			<p align="left"><b>NextHop (the most used) </b></p>
				<ul type="circle">
				
				<%
					try{
						String[] nextH= (String[])session.getAttribute( "nextH");
						String[] n1= nextH[0].split("_");
						String[] n2= nextH[1].split("_");
						String[] n3= nextH[2].split("_");
					
						out.println( "<li>"+n1[0]+": &nbsp;&nbsp;"+n1[1]+" routes </li>");
						out.println( "<li>"+n2[0]+": &nbsp;&nbsp;"+n2[1]+" routes </li>");
						out.println( "<li>"+n3[0]+": &nbsp;&nbsp;"+n3[1]+" routes </li>");
					}catch( NullPointerException e){ }
				%> 				
				</ul>
			<br />
		
			<p><b>AS that send more information</b></p>
				<ul type="circle">
				<%
					try{
						String[] as= (String[])session.getAttribute( "as");
						String[] a1= as[0].split("_");				
						String[] a2= as[1].split("_");
						String[] a3= as[2].split("_");
						
						out.println( "<li>"+a1[0]+": &nbsp;&nbsp;"+a1[1]+" messages sent </li>");
						out.println( "<li>"+a2[0]+": &nbsp;&nbsp;"+a2[1]+" messages sent </li>");
						out.println( "<li>"+a3[0]+": &nbsp;&nbsp;"+a3[1]+" messages sent </li>");
					}catch( NullPointerException e){ }
				%>
				</ul>
			<br />
		</td>
		
		</tr>
	</table>
	</center>
	<br />
	<hr />
	<br />
	
	<center>
	<h3 style="color: #000066;">Change Repository</h3>		
		
	<table align=center border=0>
		<tr>
		<td width="50%" align=center>
		<form name="selectSource" action="http://<% out.print( host);%>:8080/AnalyzerBgp/Analyzer" method="POST">
		<fieldset>
		  <legend>Select one</legend>
			<select name="noti">
			<optgroup label="siti">
				<%
					String option= repNoti.createHtml();
					out.println( option);
				%>
   			   
			</optgroup>
			</select>
			<button type="submit">
   				submit
 			</button>
		</fieldset>
		</form>
		</td>

		<td width="50%" align=center>
		<form name="newSource" action="http://<% out.print( host);%>:8080/AnalyzerBgp/Analyzer" method="POST">
		<fieldset>
		  <legend>Insert new Source </legend>
			<label>URL: <input name="nuovo" type="text"></label>
			<button type="reset">
   				reset
 			</button>
		 	<button type="submit">
   				submit
 			</button>
		</fieldset>
		</form>
		</td>
		</tr>
	</table>
	<br />

	<table>
		<tr>
		<td>
			<form name="stopThread" action="http://<% out.print( host);%>:8080/AnalyzerBgp/Analyzer" method="POST">
			<fieldset>
			  <legend style="color: #990000;">Stop Monitoring</legend>
				<select name="canc">
				<optgroup label="siti">
					<%
					String opt= repNoti.createHtml();
					out.println( opt);
					%>
				</optgroup>
				</select>
				<button type="submit" style="color: #990000;">
   					stop
	 			</button>
	 			</fieldset>
	 			</form>
		</td>
		</tr>
	</table>
	<br />
	</center>    
</body>

</html>