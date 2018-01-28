<%
    String s = request.getParameter("server");
    String start = request.getParameter("StartTime");
%>

<center>

  <form id="aform">
    <select id="choicemenu" size="1" onchange="window.open(this.options[this.selectedIndex].value,'_top')">
      <option value="nothing" selected="selected"> </option>
      <option value="index.jsp?mod=sdetails&server=<%=s%>&StartTime=10">Last 10 Minutes</option>
      <option value="index.jsp?mod=sdetails&server=<%=s%>&StartTime=60">Last Hour</option>
      <option value="index.jsp?mod=sdetails&server=<%=s%>&StartTime=180">Last 3 Hours</option>
    </select>
  </form>

  <table>
    <tr><td><fieldset><legend>Server <%=s%></legend>
       <table>
         <tr><td><img src="ServletBarChart?server=<%=s%>&StartTime=<%=start%>&Title=kb per second"/></td></tr></fieldset>
       </table>
    </td></tr>
  </table>

</center>
