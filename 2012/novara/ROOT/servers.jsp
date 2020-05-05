<%
    String start = request.getParameter("StartTime");
%>

<center>

<form id="aform">
  <select id="choicemenu" size="1" onchange="window.open(this.options[this.selectedIndex].value,'_top')">
    <option value="nothing" selected="selected"> </option>
    <option value="index.jsp?mod=servers&StartTime=10">Last 10 Minutes</option>
    <option value="index.jsp?mod=servers&StartTime=60">Last Hour</option>
    <option value="index.jsp?mod=servers&StartTime=180">Last 3 Hours</option>
  </select>
</form>

  <table>
     <tr><td><fieldset>
	<legend>Last <%=start%> Minutes</legend>
        <table>
          <tr><td align ="center">
	    <div> 
		<jsp:include page="ServersAnalysis" >
		<jsp:param name="StartTime" value="<%=start%>" />
		</jsp:include>
	    </div>
	  </td></tr>
	  </fieldset>
	</table>
     </td></tr>
  </table>
</center>
