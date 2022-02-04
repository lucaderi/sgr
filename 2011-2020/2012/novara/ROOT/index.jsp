<!DOCTYPE HTML>
<html>
  <head>
    <style type="text/css">

        BODY {FONT-FAMILY: 'Lucida Grande'; FONT-SIZE:12px; margin:0; background-color:#E4E4E4; padding:8px 0 0 0;}

        CHECKBOX,SELECT,INPUT,TEXTAREA {background-color: #E4E4E4; FONT-SIZE: 10px;}
        TR TD,P,DIV {border:10px; FONT-SIZE: 10px; COLOR: #000000; }
        TABLE {border:10px; background-color: #E4E4E4;}

        A {text-decoration: none; COLOR: #000080; FONT-SIZE: 10px;}
        A:link {text-decoration: none; COLOR: #000080; FONT-SIZE: 10px;}
        A:hover {text-decoration: none; COLOR: #000080; FONT-SIZE: 10px;}
        A:visited {text-decoration: none; COLOR: #000080; FONT-SIZE: 10px;}

    </style>
  </head>
  <body>


<center>HTTP Traffic Analyzer
<br>
<br>
<br>


<table>
<tr><td><A HREF="index.jsp?&mod=hosts">Hosts Analysis</A></td><td> | </td><td><A HREF="index.jsp?&mod=servers">Servers Analysis</A></td></tr>
</table>


  <%  if( "hosts".equals(request.getParameter("mod")) && request.getParameter("StartTime")!= null ){  
      	String start = request.getParameter("StartTime");
  %>
	<jsp:include page="hosts.jsp" >
	<jsp:param name="StartTime" value="<%=start%>" />
	</jsp:include>

  <%  } else if("hdetails".equals(request.getParameter("mod")) && request.getParameter("StartTime")!= null) {  
	String client = request.getParameter("client");
	String start = request.getParameter("StartTime");
  %>
	<jsp:include page="hdetails.jsp" >
	<jsp:param name="client" value="<%=client%>" />
	<jsp:param name="StartTime" value="<%=start%>" />
	</jsp:include>

  <%  } else if("servers".equals(request.getParameter("mod")) &&  request.getParameter("StartTime")== null) {  %>
	<jsp:include page="servers.jsp" >
        <jsp:param name="StartTime" value="10" />
        </jsp:include>
  <%  } else if("servers".equals(request.getParameter("mod")) && request.getParameter("StartTime")!= null) {  
	String start = request.getParameter("StartTime");
  %>
	<jsp:include page="servers.jsp" >
        <jsp:param name="StartTime" value="<%=start%>" />
        </jsp:include>

  <%  } else if("servers".equals(request.getParameter("mod"))) {  %>
	<%@include file="servers.jsp"%>

  <%  } else if("sdetails".equals(request.getParameter("mod"))) {  
	String server = request.getParameter("server");
	String start = request.getParameter("StartTime");
  %>
	<jsp:include page="sdetails.jsp" >
	<jsp:param name="server" value="<%=server%>" />
	<jsp:param name="StartTime" value="<%=start%>" />
	</jsp:include>

  <%  }  else { %>
	<jsp:include page="hosts.jsp" >
        <jsp:param name="StartTime" value="10" />
        </jsp:include>
  <%  }  %>


  </body>
</html>
