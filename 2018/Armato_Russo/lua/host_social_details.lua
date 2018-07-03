
dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"

sendHTTPHeader('text/html')

local hostTable = interface.getLocalHostsInfo()
if (hostTable == nil) then
	print("Non ci sono host nella rete locale")
	return
end
local host_ip = _GET["host"]
local ips = hostTable.hosts
if(host_ip ~= nil and ips[host_ip] == nil) then
	print("L'ip selezionato non appartiene alla rete locale")
	return
end

print [[
    <meta charset="utf-8"/>
]]

print [[
    <link href="/css/pie-chart.css" rel="stylesheet">
	<link href="/css/dc.css" rel="stylesheet">
	<script>var refresh = 3000 /* ms */;</script>
	<script type="text/javascript" src="/js/jquery_bootstrap.min.js"></script>
    <script type="text/javascript" src="/js/table_updater.js"></script>
    <script type="text/javascript" src="/js/pie-chart.js" ></script> 
	
    <style>
        th, td {
            border-bottom: 1px solid #ddd; 
            padding: 10px 0;
        }
        
        .stats-t table { 
            width: 100%;
            height: 25%;
            white-space:nowrap;
            border-collapse: separate;
            border-spacing: 50px 0;
        }
        
        .custom-select {
            text-align: center;
            width: auto;
            height: 50px;
        }
        
        .cs {
            display: block;
            margin: 0 auto;
        }
    </style>
    ]]
        

if(host_ip ~= nil) then
print [[
<script type="text/javascript">
// Al caricamento della finestra crea tutti i grafici e la tabella più i timer
window.onload = function(){
	do_pie("#durationPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "duration" }, "secondi", refresh);
   	do_pie("#bytesPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "bytes" }, "byte", refresh);
	do_pie("#packetsPieChart", '/lua/social_stats.lua', { host:]]print("\""..host_ip.."\"")print[[, p_metric: "packets" }, "packets", refresh);
   	update_social_table(]]print("\""..host_ip.."\"")print[[);
	setInterval(function(){ update_social_table(]]print("\""..host_ip.."\"")print[[);}, refresh);
}
</script>
]]
end

print [[
<script type="text/javascript">
function ip_changed() {
	// Carica la nuova pagina con le statistiche dell'ip selezionato
	var selectBox = document.getElementById("selectBox");
    var selectedValue = selectBox.options[selectBox.selectedIndex].value;
	window.location.search = '?host='+ selectedValue;
}
</script>
]]

print [[
    <div class="custom-select" >
        <select class="cs" id="selectBox" onchange="ip_changed()">
        <option disabled selected value> -- Select an option -- </option>
</div>
]]

for ip,_ in pairs(ips) do
    print("<option ")
	if(ip == host_ip) then 
		-- Imposto come selezionato l'ip corrente
		print(" selected") 
	end
	print(" value="..ip..">"..ip.."</option>")
end
print("</select>")


if(host_ip ~= nil) then
	-- Se ho selezionato un ip e devo visualizzare le statistiche
	print [[
	<table class="table">
	<tbody>
	<tr>
	<th class="text-left">Duration Chart</th>
	<td colspan="2">
	<div class="pie-chart" id="durationPieChart"></div>
	</td>
	</tr>
	<tr>
	<th class="text-left">Bytes Chart(sent + rcvd)</th>
	<td colspan="2">
	<div class="pie-chart" id="bytesPieChart"></div>
	</td>
	</tr>
	<tr>
	<th class="text-left">Packets Chart(sent + rcvd)</th>
	<td colspan="2">
	<div class="pie-chart" id="packetsPieChart"></div>
	</td>
	</tr>
	</tbody>
	</table>
	<div class ="stats-t" id="stats_table"></div>
	]]
end



