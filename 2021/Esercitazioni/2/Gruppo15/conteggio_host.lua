

-- Per tutti i protocolli
-- numero di hosts diversi contattati (client)
-- numero di hosts diversi da cui sono stati contattati (server)

--[[
	Il client si intente colui che inizia la comunicazione 
	(quelloc he manda il SYN in TCP per intenderci, 
	mentre su UDP chi della 5-tupla IP src/dst,ports src/dst e protocollo invia il pacchetto per primo).
	Per semplicita’ potreste considerare le coppie IP src - IP dst 
	lasciando il discorso client/server a quando vi spiego meglio come analizzare questi dati
]]--


-- Field Extractors
local f_tcp_connection_syn = Field.new("tcp.connection.syn")

local f_udp = Field.new("udp")

local f_ip_source = Field.new("ip.src")
local f_ip_dest   = Field.new("ip.dst")



local function getstring(finfo)
	local ok, val = pcall(tostring, finfo) -- pcall chiama la funzione passata come parametro e restituisce una coppia
										   -- <esito, par_returned> 
	if not ok then val = "(unknown)" end
	return val
end


local function ratio_tap()
	-- Declare the window we will use (dummy ecc sarebe il titolo)
	local tw = TextWindow.new("Rapporto richieste DNS eseguite e risposte ricevute")
	
	-- lista degli host che ci contattano, lista degli host contattati
	local ip_client = {}
	local ip_server = {}


	-- this is our tap
	local tap = Listener.new();

	
	local function remove()
		-- this way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- we tell the window to call the remove() function when closed
	tw:set_atclose(remove)


	-- this function will be called once for each packet
	function tap.packet(pinfo,tvb) -- Testy Virtual Buffer
		local tcp_connection_syn = f_tcp_connection_syn()
		local udp = f_udp()

		local ip_source = f_ip_source()
		local ip_dest = f_ip_dest()

		if(tcp_connection_syn ~= nil or udp ~= nil) then

			if( ip_source ~= nil) then

				local ip = getstring(ip_source)
				local val1, val2, val3, val4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
				local ok1, ip1 = pcall(tonumber, val1)
				local ok2, ip2 = pcall(tonumber, val2)
				local ok3, ip3 = pcall(tonumber, val3)
				local ok4, ip4 = pcall(tonumber, val4)

				-- vedere caso multicast


				-- caso in cui sono un client
				if(ok1 ~= nil and ok2 ~= nil and ok3 ~= nil and ok4 ~= nil) then
					if(ip1 == 192 and ip2 == 168 and ip3 == 1 and ip4 > 0 and ip4 < 255) then 
						
						if(ip_dest ~= nil) then
							local tmp = tostring(ip_dest)
							ip_server[tmp] = 0
						end		
					else  -- caso in cui sono server  
					
						ip_client[ip] = 0
					end
				end
			end
		end
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
    	tw:clear()
    	local cont_client = 0
    	local cont_server = 0


    	-- totale dei tcp

    	for ip, tmp in pairs(ip_client) do

    		cont_client = cont_client + 1
    	end

    	for ip, tmp in pairs(ip_server) do

    		cont_server = cont_server + 1
    	end


    	tw:append("Totale host contattati:\t" .. cont_server .. "\n" .. "Totale host che ci hanno contattato: \t".. cont_client .. "\n");
    end

   -- this function will be called whenever a reset is needed
   -- e.g. when reloading the capture file
   function tap.reset()
      tw:clear()
      ip_server = {}
      ip_client = {}
   end

   -- Ensure that all existing packets are processed.
   retap_packets()
end


-- Menu GR -> Packets
register_menu("GR/Conta_Host/Packets", ratio_tap, MENU_TOOLS_UNSORTED)







