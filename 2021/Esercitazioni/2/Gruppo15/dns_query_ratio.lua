
-- Field Extractors
local f_dns_query_name    = Field.new("dns.qry.name")
local f_dns_response_in   = Field.new("dns.response_in")
local f_dns_response_to	  = Field.new("dns.response_to")


local function getstring(finfo)
	local ok, val = pcall(tostring, finfo) -- pcall chiama la funzione passata come parametro e restituisce una coppia
											  -- <esito, par_returned> 
	if not ok then val = "(unknown)" end
	return val
end


local function ratio_tap()
	-- Declare the window we will use (dummy ecc sarebe il titolo)
	local tw = TextWindow.new("Rapporto richieste DNS eseguite e risposte ricevute")
	
	-- contiene tutti i nomi delle query incontrate
	local dns_queries = {}

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
		local dns_query_name  = f_dns_query_name() -- Call the function that extracts the field
		local dns_response_in = f_dns_response_in()
		local dns_response_to = f_dns_response_to()
		local e1 = 0
		local e2 = 0

		-- per un determinato host controllo se è una query che ha rivevuto una risposta, oppure se
		-- è una query che non ha ricevuto una risposta. In base all'esito del controllo
		-- aggiorno la coppia e1,e2 che sarebbero rispettivamente query_con_risp,query_senza
		if(dns_query_name ~= nil) then

			dns_query_name = getstring(dns_query_name) -- get the string returned by the query name
	 		
	 		tmp = dns_queries[dns_query_name]
	 		
	 		if(tmp ~= nil) then
	 			e1,e2 = tmp
	 		end
	 		
	 		if(dns_response_in ~= nil) then

	 				e1 = e1 + 1
			else

				if(f_dns_response_to == nil) then

						e2 = e2 +1
				end

			end

			
			dns_queries[dns_query_name] = e1, e2
		end
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
    	tw:clear()
    	local tot
    	local rt
    	local tmp, tmp2, tmp3

    	for dns_query, tmp3 in pairs(dns_queries) do
    		
    		tot = 0
    		ok, notok = tmp3

    		if(notok ~= nil) then
    			tot = notok
    		end

    		if(ok ~= nil) then 
    			tot = tot + ok
    			rt = tot / ok
    		else
    			rt = tot / 0
    		end

    		tw:append(dns_query .. "\t" .. "query_fatte/riposte = " .. rt .. "\n");

    	end
    end

   -- this function will be called whenever a reset is needed
   -- e.g. when reloading the capture file
   function tap.reset()
      tw:clear()
      dns_queries = {}
   end

   -- Ensure that all existing packets are processed.
   retap_packets()
end


-- Menu GR -> Packets
register_menu("GR/Ratio_dns/Packets", ratio_tap, MENU_TOOLS_UNSORTED)




