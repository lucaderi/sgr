-- [DONE] Creare una lista che visualizzi tutti gli ip locali e a seconda
--		dell'ip selezionato fa vedere tutti i grafici.
-- TODO Riguardare le metriche ed unità di misura che ci sono nei grafici (sembrano sbagliate) le mostra diviso mille ( mi sembra)
-- [DONE] Aggiungere una tabella alla fine che display dei dati raw (OPZIONALE)
-- TODO Perché nel jquery_bootstrap.min.js noi non abbiamo parametri ma lui si?
-- TODO Scrivere un po' di CSS per le tabelle con i grafici (oppure usare i suoi)
-- [TODO] Vedere cosa fare nella pagine generale senza nessun IP selezionato

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"
require "graph_utils"
--font-awesome.css è figo

--[[ Questi sembrano non servire
<script type="text/javascript" src="/js/deps.min.js"></script>
	<script type="text/javascript" src="/js/ntop.min.js"></script>
--]]
sendHTTPHeader('text/html')

print [[
    <meta charset="utf-8"/>
]]

print [[
    <link href="/css/pie-chart.css" rel="stylesheet">
	<link href="/css/dc.css" rel="stylesheet">
	
	<script type="text/javascript" src="/js/jquery_bootstrap.min.js"></script>
    <script type="text/javascript" src="/js/table_updater.js"></script>
    <script type="text/javascript" src="/js/pie-chart.js" ></script>   
	<script>var refresh = 3000 /* ms */;</script>
    <style>
        table, th, td 
        {
            margin:10px 0;
            border:solid 1px #333;
            padding:2px 4px;
            font:15px Verdana;
        }
        th {
            font-weight:bold;
        }
    </style>
    ]]
        
local host_ip = _GET["host"]
if(host_ip ~= nil) then
print [[
<script type="text/javascript">
	window.onload = function(){
	do_pie("#durationPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "duration" }, "secondi", refresh);
    do_pie("#bytesPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "bytes" }, "byte", refresh);
	do_pie("#packetsPieChart", '/lua/social_stats.lua', { host:]]print("\""..host_ip.."\"")print[[, p_metric: "packets" }, "packets", refresh);
    update_social_table(]]print("\""..host_ip.."\"")print[[);
	setInterval(function(){
		update_social_table(]]print("\""..host_ip.."\"")print[[);
	}, refresh);
   }

</script>
]]
end

print [[
<script type="text/javascript">
   function changeFunc() {
    var selectBox = document.getElementById("selectBox");
    var selectedValue = selectBox.options[selectBox.selectedIndex].value;
	window.location.search = '?host='+ selectedValue;
	}
</script>
  ]]

local hostTable = interface.getLocalHostsInfo()
if (hostTable == nil) then
	print("No local hosts in the network")
	return
end


print [[
<select id="selectBox" onchange="changeFunc()">
]]
local ips = hostTable.hosts
for ip,_ in pairs(ips) do
    print("<option ")
	if(ip == host_ip) then 
		print(" selected") 
	end
	print(" value="..ip..">"..ip.."</option>")
	--print("<option value=< a>"..ip.."</option>")
end

print("</select>")

if(host_ip ~= nil) then
print [[<table class="table table-bordered table-striped">
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
	]]

print [[
        <div id="showData"></div>
        ]]
end




