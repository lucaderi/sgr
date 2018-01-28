<%
    String c = request.getParameter("client");
    String start = request.getParameter("StartTime");
%>

<form id="form">
  <select id="choicemenu" size="1" onchange="window.open(this.options[this.selectedIndex].value,'_top')">
    <option value="nothing" selected="selected"> </option>
    <option value="index.jsp?mod=hdetails&client=<%=c%>&StartTime=10">Last 10 Minutes</option>
    <option value="index.jsp?mod=hdetails&client=<%=c%>&StartTime=60">Last Hour</option>
    <option value="index.jsp?mod=hdetails&client=<%=c%>&StartTime=180">Last 3 Hours</option>
  </select>
</form>

<center>
  <table>
    <tr><td><fieldset><legend>Last <%=start%> Minutes of <%=c%> </legend>
       <table>
         <tr><td align ="center">
	     <div>
        	<jsp:include page="HostDetails" >
        	<jsp:param name="client" value="<%=c%>" />
        	<jsp:param name="StartTime" value="<%=start%>" />
        	</jsp:include>
             </div>
	 </td></tr>
         <tr><td align ="center"><img src="ServletBarChart?client=<%=c%>&StartTime=<%=start%>&Title=kb per second""/></td></tr>
	   </fieldset>
        </table>
     </td></tr>
   </table>
</center>
