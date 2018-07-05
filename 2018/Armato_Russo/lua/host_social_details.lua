
dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"

if(mode ~= "embed") then
   sendHTTPContentTypeHeader('text/html')
   ntop.dumpFile(dirs.installdir .. "/httpdocs/inc/header.inc")
   active_page = "hosts"
   dofile(dirs.installdir .. "/scripts/lua/inc/menu.lua")
end

local hostTable = interface.getLocalHostsInfo()

if (hostTable == nil) then
	print("Non ci sono host nella rete locale")
	return
end

local host_ip = _GET["host"]
local ips = hostTable.hosts

if(host_ip == nil) then
	print("Inserire un host come parametro.")
	return
end

if(host_ip ~= nil and ips[host_ip] == nil) then
	print("L'ip selezionato non appartiene alla rete locale")
	return
end

print [[
	<script>var refresh = 3000 /* ms */;</script>
    <script type="text/javascript" src="/js/table_updater.js"></script>
  
    <style>
        .stats-t table { 
            width: 100%;
            height: 25%;
            white-space:nowrap;
            border-collapse: separate;
            border-spacing: 50px 0;
        }
		
		.pie-chart {
			font-size: inherit;	
		}
    </style>
]]
        

if(host_ip ~= nil) then

print [[
<script type="text/javascript">
function show_data(){
	var charts = document.getElementsByClassName("pie-chart");
	var i;
	for (i = 0; i < charts.length; i++) {
    	charts[i].innerHTML = "";
	}
	update_social_table(]]print("\""..host_ip.."\"")print[[) 
	do_pie("#durationPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "duration" }, "secondi", refresh);
   	do_pie("#bytesPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "bytes" }, "byte", refresh);
	do_pie("#packetsPieChart", '/lua/social_stats.lua', { host:]]print("\""..host_ip.."\"")print[[, p_metric: "packets" }, "packets", refresh);
	setInterval(function(){ update_social_table(]]print("\""..host_ip.."\"")print[[);}, refresh);
}
</script>

<script type="text/javascript">
// Controlla ad intervalli che ci siano dati da mostrare
function check_data(ip){
	$.ajax({
		type : 'GET',
		url: "/lua/social_stats",
		data: "host="+ip,
		success: function(content){
			var metrics=JSON.parse(content)
			if(metrics != ""){
				clearInterval(refreshId);
				show_data();
			}else{
				var charts = document.getElementsByClassName("pie-chart");
				var i;
				for (i = 0; i < charts.length; i++) {
    				charts[i].innerHTML = "Non ci sono dati da mostrare momentaneamente. La pagina si aggiornerà automaticamente.";
				}
			}
  		}
	})
}
</script>

<script type="text/javascript">
// Al caricamento della finestra controlla se ci sono dati
window.onload = function(){
	check_data("]]print(host_ip)print[[");
	refreshId = setInterval(function(){check_data("]]print(host_ip)print[[");}, refresh);
}
</script>

]]

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

if(mode ~= "embed") then
	dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")
end
