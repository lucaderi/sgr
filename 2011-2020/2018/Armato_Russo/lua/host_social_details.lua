
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
    
]]
        

if(host_ip ~= nil) then

print [[
<script type="text/javascript">

function update_social_table() {
  $.ajax({
    type: 'GET',
    url: ']]
  print(ntop.getHttpPrefix())
  print [[/lua/social_stats.lua',
    data: { host: "]] print(host_ip.."") print ("\" ")

    print [[ },
    success: function(content) {
        $('#host_details_social_tbody').html(content);
        $('#myTable').trigger("update");
    }
    
  });
}
</script>


<script type="text/javascript">
function show_data(){
	var charts = document.getElementsByClassName("pie-chart");
	var i;
	for (i = 0; i < charts.length; i++) {
    	charts[i].innerHTML = "";
	}
    update_social_table();
	do_pie("#durationPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "duration" }, "", refresh);
   	do_pie("#bytesPieChart", '/lua/social_stats.lua', { host: ]]print("\""..host_ip.."\"")print[[, p_metric: "bytes" }, "", refresh);
	do_pie("#packetsPieChart", '/lua/social_stats.lua', { host:]]print("\""..host_ip.."\"")print[[, p_metric: "packets" }, "", refresh);
    setInterval(update_social_table, refresh);
}
</script>

<script type="text/javascript">
// Controlla ad intervalli che ci siano dati da mostrare
function check_data(ip){
	$.ajax({
		type : 'GET',
		url: "/lua/social_stats",
		data: "host="+ip+"&p_metric=packets",
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
	<th class="text-left">Bytes Chart(sent + received)</th>
	<td colspan="2">
	<div class="pie-chart" id="bytesPieChart"></div>
	</td>
	</tr>

	<tr>
	<th class="text-left">Packets Chart(sent + received)</th>
	<td colspan="2">
	<div class="pie-chart" id="packetsPieChart"></div>
	</td>
	</tr>

	</tbody>
	</table>

    <table id="myTable" class="table table-bordered table-striped tablesorter">
        <thead>
            <tr>
                <th>Application Name</th>
                <th>Duration</th>
                <th>Packets Received</th>
                <th>Packets Sent</th>
                <th>Packets Breakdown</th>
                <th>Total Packets</th>
                <th>Bytes Received</th>
                <th>Bytes Sent</th>
                <th>Bytes Breakdown</th>
                <th>Total Bytes</th>
            </tr>
        </thead>
        
        <tbody id="host_details_social_tbody"></tbody>
     </table>
	
	]]
end

if(mode ~= "embed") then
	dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")
end
