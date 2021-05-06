--Per tutti i protocolli
--- numero di hosts diversi contattattati (client)
--- numero di hosts diversi da cui sono stati contattati (server)
--per tutti i protocolli intendevo “a prescindere dal protocollo” ovvero senza differenziare DNS o TLS ad esempio.
--Per fare qeusto esercizio usate pure una hash o simile, anche se poi tra un pochino vi faccio vedere delle strutture dati ad hoc a lezione
--(es vd https://github.com/avz/hll). 
--Il client si intente colui che inizia la comunicazione 
--(quelloc he manda il SYN in TCP per intenderci,
--mentre su UDP chi della 5-tupla IP src/dst,ports src/dst e protocollo invia il pacchetto per primo). Per semplicita’ potreste considerare
--le coppie IP src-IP dst lasciando il discorso client/server a quando vi spiego meglio come analizzare questi dati. 
-- Non metterei di certo un parametro nel codice.

local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_udp_src_port = Field.new("udp.srcport")
local f_udp_dst_port = Field.new("udp.dstport")
local f_tcp_flags  = Field.new("tcp.flags")
local f_tcp_flags_syn  = Field.new("tcp.flags.syn")
local f_tcp_flags_ack  = Field.new("tcp.flags.ack")

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

local function isMulticast(v_ip_dst)

	if (v_ip_dst == nil) then
		return
	end

	local ip = tostring(v_ip_dst.value)
	local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )

	if (o1 == nil or o2 == nil or o3 == nil or o4 == nil) then
		return true
	end

	local ok1, val1 = pcall(tonumber, o1)
	local ok2, val2 = pcall(tonumber, o2)
	local ok3, val3 = pcall(tonumber, o3)
	local ok4, val4 = pcall(tonumber, o4)

	if (not (ok1 and ok2 and ok3 and ok4)) then
		return true
	end
	if (val1 >= 224 and val1 <= 239) then
		return true
	end
	-- Also check for the standard local broadcast 192.168.1.255
	if ( val1 == 192  and  val2 == 168  and  val3 == 1  and  val4 == 255 ) then
		return true
	end

	return false

end

local function clientIpFinder(list, new_ip_src, new_ip_dst)

	-- If dst is multicast src can be either the client (if he sends
	-- 	it), or someone else on the network, so we discard the packet
	--	because it gives us no new information.
	if (isMulticast(new_ip_dst)) then
		return nil
	end

	-- Base case for fist packet
	if (next(list) == nil) then
		table.insert(list, new_ip_src.value)
		table.insert(list, new_ip_dst.value)
		return nil
	end

	-- If both IPs are the same (in one direction or the other), we don't
	--	gain any other information about what could be the client's IP.
	if (   (list[1] == new_ip_src.value and list[2] == new_ip_dst.value)
		or (list[2] == new_ip_src.value and list[1] == new_ip_dst.value) ) then
		return nil
	end

	-- Since our IP must appear either on src or dst (exlcuding multicast
	--	packets which we already discarded) there must be at least a field
	--	containing it. Also, it can't be that both IPs are equal to our
	--	candidates IP because we already checked that in the previous if.
	-- So if we find an intersection between either the src IP or the dst
	--	IP with our candidates IP, then we have found the client IP. 
	if (list[1] == new_ip_src.value or list[2] == new_ip_src.value) then
		return new_ip_src.value
	end
	if (list[1] == new_ip_dst.value or list[2] == new_ip_dst.value) then
		return new_ip_dst.value
	end

	-- This statement should never be executed because we already worked
	--	on all cases. However we should leave it there in case of rare
	--	edge cases.
	return nil

end

function desc(a,b) return (a > b) end

function sortHosts(hosts_list)

	-- Array that will contain a distinct host for each element.
	--	Each element 'a' will contain two elements,
	--	a[1] = host_name, a[2] = number of ports.
	local hosts_port_count = {}
	local index = 1

	for host,ports in pairs(hosts_list) do

		hosts_port_count[index] = {}
		hosts_port_count[index][1] = host
		hosts_port_count[index][2] = 0

		for port in pairs(ports) do
			hosts_port_count[index][2] = hosts_port_count[index][2] + 1
		end

		index = index + 1

	end

	-- sort the function by the number of ports.
	table.sort(hosts_port_count, function(x,y) return desc(x[2], y[2]) end)
	return hosts_port_count

end

local function gr_tap()
	-- Declare the window we will use
	local tw = TextWindow.new("Client Server")
	
	-- Dictionary key:hostname value:boolean representing its presence ad client
	local clients_tcp = {}
	local servers_tcp = {}
	local hosts_udp = {}
	local clients_udp = {}
	local servers_udp = {}

	local candidate_client_ips_list = {}
	local client_ip = nil

	-- this is our tap
	local tap = Listener.new();

	local function remove()
		-- this way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- we tell the window to call the remove() function when closed
	tw:set_atclose(remove)

	-- this function will be called once for each packet
	function tap.packet(pinfo,tvb)
		-- Call all the function that extracts the fields
		local ip_src = f_ip_src()
		local ip_dst = f_ip_dst()
		local src_port = f_udp_src_port()
		local dst_port = f_udp_dst_port()
		local tcp_flags = f_tcp_flags()
		local tcp_flags_syn = f_tcp_flags_syn() 
		local tcp_flags_ack = f_tcp_flags_ack()

		if (ip_src == nil or ip_dst == nil) then 
			return 
		end

		if (client_ip == nil) then
			client_ip = clientIpFinder(candidate_client_ips_list, ip_src, ip_dst)
		end

		--Check if it's a tcp packet and contains an IP source (maybe we can't get src information a non-IP datagram)
		if(tcp_flags ~= nil) then
			--Check if the SYN flag is 1 (if it isn't it's just a TCP segment of an already enstablished connection)
			if(tcp_flags_syn.value) then
				--If ACK is set to 1 then the src is the Server that sends the second segment of the 3 way handshake 
				if(tcp_flags_ack.value) then
					if(servers_tcp[getstring(ip_src.value)] == nil) then
						servers_tcp[getstring(ip_src.value)] = true
					end
				--Else is the client that starts the communication with just a SYN
				else
					if (clients_tcp[getstring(ip_src.value)] == nil) then
						clients_tcp[getstring(ip_src.value)]= true
					end
				end

			end 
		end
		
		if(src_port ~= nil and dst_port ~= nil) then

			if(hosts_udp[getstring(ip_src.value)] == nil) then
				hosts_udp[getstring(ip_src.value)] = {}
			end
			if(hosts_udp[getstring(ip_dst.value)] == nil) then
				hosts_udp[getstring(ip_dst.value)] = {}
			end
			
			hosts_udp[getstring(ip_src.value)][getstring(src_port.value)] = true
			hosts_udp[getstring(ip_dst.value)][getstring(dst_port.value)] = true

		end

	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		
		tw:clear()
		local tot_clients_tcp = 0
		local tot_servers_tcp = 0
		local tot_hosts_udp = 0
		local tot_clients_udp=0
		local tot_servers_udp=0

		tw:append("TCP \n")
		tw:append("\tClients: " .. "\n")
		for host,flag in pairs(clients_tcp) do
			tw:append("\t\t" .. getstring(host) .. "\n")
			if(flag) then
				tot_clients_tcp = tot_clients_tcp + 1
			end
		end

		tw:append("\tServers: " .. "\n")
		for host,flag in pairs(servers_tcp) do
			tw:append("\t\t" .. getstring(host) .. "\n")
			if(flag) then
				tot_servers_tcp = tot_servers_tcp + 1
			end
		end

		tw:append("\tTotal TCP clients: " .. tot_clients_tcp .. "\n")
		tw:append("\tTotal TCP servers: " .. tot_servers_tcp .. "\n")

		tw:append("\n")

		tw:append("UDP: \n")
		local hosts_port_count = sortHosts(hosts_udp)

		if (client_ip == nil) then
			
			tw:append("\tThe script could not identify the client's IP so the\n")
			tw:append("\tfollowing hosts can't be labelled as either 'Client' or 'Server'\n")

			tw:append("\t\tHost\tNumber of services\n")

			for index,host in ipairs(hosts_port_count) do
				tot_hosts_udp = tot_hosts_udp + 1
				tw:append("\t\t" .. getstring(host[1]) .. "\t" .. getstring(host[2]) .. "\n")
			end

		else

			-- While printing the clients, save the servers for the second
			--	print, to avoid going through the loop and the if again.
			local servers_port_count = {}

			tw:append("\tClients: " .. "\n")
			tw:append("\t\tHost\tNumber of services\n")
			for index,host in ipairs(hosts_port_count) do

				tot_hosts_udp = tot_hosts_udp + 1

				if (host[1] == getstring(client_ip)) then
					tot_clients_udp = tot_clients_udp + 1
					tw:append("\t\t" .. getstring(host[1]) .. "\t" .. getstring(host[2]) .. "\n")
				else
					tot_servers_udp = tot_servers_udp + 1
					servers_port_count[tot_servers_udp] = host
				end

			end

			tw:append("\tServers: " .. "\n")
			tw:append("\t\tHost\tNumber of services\n")
			for index,server in ipairs(servers_port_count) do
				tw:append("\t\t" .. getstring(server[1]) .. "\t" .. getstring(server[2]) .. "\n")
			end

			tw:append("\tTotal UDP clients: " .. tot_clients_udp .. "\n")
			tw:append("\tTotal UDP servers: " .. tot_servers_udp .. "\n")

		end

	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		clients_tcp = {}
		servers_tcp = {}
		hosts_udp = {}
		clients_udp = {}
		servers_udp = {}
		candidate_client_ips_list = {}
		client_ip = nil
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- Menu GR -> Packets
register_menu("Gruppo9/Client Server", gr_tap, MENU_TOOLS_UNSORTED)

--if gui_enabled() then
--   local splash = TextWindow.new("Hello!");
--   splash:set("Wireshark has been enhanced with a usefull feature.\n")
--   splash:append("Go to 'Tools->Gruppo9' and check it out!")
--end