<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%! String host;%>
<%  
	host = java.net.InetAddress.getLocalHost().getHostAddress();
%>

<jsp:useBean id="note" class="analyzer.Repository" scope="session"/>

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
		<h5>(start page)</h5>
		<br />
		<h2 style="color: #000066;">Select or enter a new files repository</h2>
		<br />
		<center>
			<table align=center border=0>
				<tr>
					<td width="50%" align=center>
						<form name="selectSource" action="http://<% out.print( host);%>:8080/AnalyzerBgp/Analyzer" method="POST">
						<fieldset>
		  					<legend>Select one</legend>
								<select name="noti">
								<optgroup label="siti">
								<%
									String option= note.createHtml();
									out.println( option);
								%>
								</optgroup>
								</select>
								<button type="submit">submit</button>
						</fieldset>
						</form>
					</td>

					<td width="50%" align=center>
						<form name="newSource" action="http://<% out.print( host);%>:8080//AnalyzerBgp/Analyzer" method="POST">
						<fieldset>
		  					<legend>Insert new Source </legend>
								<label>URL: <input name="nuovo" type="text"></label>
								<button type="reset">reset</button>
		 						<button type="submit">submit</button>
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
						String opt= note.createHtml();
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
	</center>
</body>

</html>