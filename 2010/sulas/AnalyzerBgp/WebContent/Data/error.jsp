<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>


<jsp:useBean id="repNoti" class="analyzer.Repository" scope="session"/>

<%!	String errore; %>
<%! String host;%>
<%  
	host = java.net.InetAddress.getLocalHost().getHostAddress();
%>


<html>
<head>
	<%
   		response.setHeader( "Pragma", "no-cache" );
   		response.setHeader( "Cache-Control", "no-cache" );
   		response.setDateHeader( "Expires", 0 );
   	%>
   	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<title>Analyzer BGP</title>
</head>

<body>	
	<center>
		<h1 style=" color: #660099;"><u>Analyzer BGP</u></h1>
		<h5>(Error Page)</h5>
		<br />		
		<br />
		<font size="15" color="#FF0000" face="arial,verdana">
		<%
			errore= (String) session.getAttribute( "desc");
		%>
		</font><br />
		<p style="color: #990000; font-size: 18pt;">
		<%
			/**
			 * possibili messaggi di errore
			 * 		IO exception, RRD/BgpDump problem			 *		
			 *		IO exception, File IO problem			 
			 *		Malformed URL			 
			 *		Response: "+status+" (bad staus)
			 *		(Internal Error) The server received a POST for an unknown URL\No parameters entered\Unknown request			 *
			 *		Comunication exception
			 *
			 * ma solamente  Malformed URL, bad status e Internal Error si verificano dopo una richiesta-utente
			 * le altre son "assincrone"
			 */
		
			if( errore.contains( "Malformed URL") || errore.contains( "bad status")){
				out.println( "<br /> Enter http://a.b.c/x <br />");
				out.println( "<br /> that must contain folders 'year.mounth'");
				out.println( "<br /> which in turn must contain files 'updates.YearMounthDay.HourMin.gz' <br />");
			}
			/*else if( errore.contains( "RRD")){
				out.println( "<br /> RRDTOOL is probably not installed! contact an admin to fix the problem");
			}
			else if( errore.contains( "BgpDump")){
				out.println( "<br /> BgpDump is probably not installed! contact an admin to fix the problem");
			}*/
			else if( errore.contains( "Internal Error") || errore.contains( "File IO")){
				out.println( "<br /> An error has occurred! contact an admin to fix the problem");
			}
			
			out.println( "<br /><sub>"+errore+"</sub><br />");
		%>
		</p>		
		<p>Please select another repository!</p>
		<br />
		<br />
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
