
-- HTTP
-- Rapporto risposte HTTP positive (es codice 200) e negative (es errori 500)



-- Field Extractors
local f_response_code  = Field.new("http.response.code")


local function getstring(finfo)
	local ok, val = pcall(tostring, finfo) -- pcall chiama la funzione passata come parametro e restituisce una coppia
											  -- <esito, par_returned> 
	if not ok then val = "(unknown)" end
	return val
end


local function ratio_tap()
	-- Declare the window we will use (dummy ecc sarebe il titolo)
	local tw = TextWindow.new("Rapporto richieste HTTP")
	
	local positive_counter = 0
	local negative_counter = 0

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
		local http_response_code  = f_response_code() -- Call the function that extracts the field
		local code_value


		-- per un determinato host controllo se è una query che ha rivevuto una risposta, oppure se
		-- è una query che non ha ricevuto una risposta. In base all'esito del controllo
		-- aggiorno la coppia e1,e2 che sarebbero rispettivamente query_con_risp,query_senza
		if(http_response_code ~= nil) then
			code_value = http_response_code.value

			if(code_value > 199 and code_value < 300) then
				positive_counter = positive_counter + 1
			else
				if(code_value > 399 and code_value < 600) then
					negative_counter = negative_counter +1
				end
			end
		end
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
    	tw:clear()
    	local rt
    	
    	if(negative_counter == 0) then
    		rt = 0
    	else
    		rt = positive_counter / negative_counter
    	end

    	tw:append("Risposte http positive/negative = " .. rt .. "\n");

    end

   -- this function will be called whenever a reset is needed
   -- e.g. when reloading the capture file
   function tap.reset()
      tw:clear()
      positive_counter = 0
      negative_counter = 0
   end

   -- Ensure that all existing packets are processed.
   retap_packets()
end


-- Menu GR -> Packets
register_menu("GR/Ratio_http_response/Packets", ratio_tap, MENU_TOOLS_UNSORTED)




