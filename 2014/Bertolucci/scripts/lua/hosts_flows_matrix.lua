--
-- (C) 2013 - ntop.org
--

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"

if(mode ~= "embed") then
   sendHTTPHeader('text/html')
   ntop.dumpFile(dirs.installdir .. "/httpdocs/inc/header.inc")
   active_page = "hosts"
   dofile(dirs.installdir .. "/scripts/lua/inc/menu.lua")
end

num_top_hosts = 10

if(host_ip == nil) then
   host_ip = _GET["host"]
   num = 1
else
   interface.find(ifname)
   hosts = interface.getHostsInfo()
   num = 0
   --[[key ritorna ip computer]]--
   --[[value e sempre null]]--
   for key, value in pairs(hosts) do
    num = num + 1
   end
end

host = interface.getHostInfo(host_ip)
if(host == nil) then
	print [[
		<style>
		@import url(/css/style_matrix.css);
		.background {
		  fill: #eee;
		}
		line {
		  stroke: #fff;
		}
		text.active {
		  font-size: 12px;
		  fill: red;
		}
		article, aside { display:inline-block; vertical-align:top;}
		
		#tooltip{
		    display: none;
		    position: absolute;
		    color : #fff;
		  	/*background-color: #333;*/
		    border-radius: 4px;
		    z-index: 1000;
		}
		
		
		tr { background-color: #333; }
		</style>
	]]
	print ('</script>')
	print("<section>")
		print("<header><h3></h3></header>")
		print('<div id="tooltip">')
		print [[
			<table class="table table-bordered">
				<thead>
					<th style="text-align: center;">Host</th>
					<th style="text-align: center;">Sent</th>
					<th style="text-align: center;">Rcvd</th>
				</thead>
				<tbody>
				</tbody>
			</table>
		]]
		print('</div>')
	  	print("<article class=\"gr\"></article>")
		print [[
		<aside style="margin-top: 90px; margin-left: 10px;>"
			<p><h4>Order: </h4><select id="order">
				<option value="name">by Name</option>
				<option value="count">by Frequency</option>
				<option value="group">by Cluster</option>
				<option value="flow_sent">by Flows Sent</option>
				<option value="flow_rcvd">by Flows Rcvd</option>
				<option value="flow_tot">by Flows Tot</option>
				</select>
			</p>
			<div id="legend" style="">
				<h4>Legend:</h4>
				<svg width="100" height="198">
					  <defs>
					    <linearGradient id="local"
					                    x1="0%" y1="0%"
					                    x2="100%" y2="100%"
					                    spreadMethod="pad">
					      <stop offset="0%"   stop-color="#1f77b4" stop-opacity="1"/>
					      <stop offset="100%" stop-color="#1f77b4" stop-opacity=".25"/>
					    </linearGradient>
					    <linearGradient id="remote"
					                    x1="0%" y1="0%"
					                    x2="100%" y2="100%"
					                    spreadMethod="pad">
					      <stop offset="0%"   stop-color="#ff7f0e" stop-opacity="1"/>
					      <stop offset="100%" stop-color="#ff7f0e" stop-opacity=".25"/>
					    </linearGradient>
					     <linearGradient id="none"
					                    x1="0%" y1="0%"
					                    x2="100%" y2="100%"
					                    spreadMethod="pad">
					      <stop offset="0%"   stop-color="#333" stop-opacity="1"/>
					      <stop offset="100%" stop-color="#333" stop-opacity=".25"/>
					    </linearGradient>
					  </defs>
					<g transform="translate(0,0)">
						<rect rx="3" ry="3" width="100" height="30" style="fill: url(#local);"></rect>
						<text x="50" y="15" dy="0.35em" text-anchor="middle">local</text>
					</g>
					<g transform="translate(0,33)">
						<rect rx="3" ry="3" width="100" height="30" style="fill: url(#remote);"></rect>
						<text x="50" y="15" dy="0.35em" text-anchor="middle">remote</text>
					</g>
					<g transform="translate(0,66)">
						<rect rx="3" ry="3" width="100" height="30" style="fill: url(#none);"></rect>
						<text x="50" y="15" dy="0.35em" text-anchor="middle">local &lt;-&gt; remote</text>
					</g>
				</svg>
			</div>
		</aside>
		]]
	print("</section>")
	print ('<script>')
	ntop.dumpFile(dirs.installdir .. "/httpdocs/js/matrix_volume.js")
	print ('</script>')
		--[[print ('<script src="/js/matrix_volume.js"></script>')]]--
else
	 print("<div class=\"alert alert-error\"><img src=/img/warning.png> No results found</div>")
end

if(mode ~= "embed") then
dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")
end