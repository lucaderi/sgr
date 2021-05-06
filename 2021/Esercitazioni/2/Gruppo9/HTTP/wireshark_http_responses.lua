--HTTP
-- Rapporto risposte HTTP positive (es codice 200) e negative (es errori 500)
-- Actually the responses of HTTP are different than only positive and negative : 
-- {broken,server error(es 500), client error, redirection , sucess response (es 200), informational}

local f_http_code = Field.new("http.response.code")
local f_ip_src = Field.new("ip.src")

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

local function gr_tap()
	-- Declare the window we will use
	local tw = TextWindow.new("HTTP Good/Bad responses ratio")

	local http_response_positive = {}
	local http_response_negative = {}

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
	
		-- Call the function that extracts the field
		local http_response_code = f_http_code()
		local ip_src =f_ip_src()

		--Check if there is an HTTP response code and an IPv4
		if(http_response_code ~= nil and ip_src ~= nil) then

			local ip_src_string = getstring(ip_src.value)

			-- The check could be done on either dictionary since
			--	..positive[ip_src_string] == nil <=> ..negative[ip_src_string] == nil 
			if (http_response_positive[ip_src_string] == nil) then
				http_response_positive[ip_src_string] = 0
				http_response_negative[ip_src_string] = 0
			end 

			--If the response code is between 199 and 300 then it's a positive response
			if (http_response_code.value > 199 and http_response_code.value < 300) then
				http_response_positive[ip_src_string] = http_response_positive[ip_src_string] + 1
			
			--Else if the response code is between 499 and 600 then it's a bad response
			elseif (http_response_code.value > 499 and http_response_code.value < 600) then
				http_response_negative[ip_src_string] = http_response_negative[ip_src_string] + 1
			
			end

		end

	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()
		for host in pairs(http_response_positive) do

			local num_positive = http_response_positive[host]
			local num_negative = http_response_negative[host]

			if (num_positive>0 and num_negative>0) then
				tw:append(host .. ":\t" .. (num_positive/num_negative) .. "\n");
			end
			if (num_positive==0 and num_negative>0) then
				tw:append(host .. ":\t" .. "Only bad responses (" .. num_negative .. " server errors)\n");
			end
			if (num_positive>0 and num_negative==0) then
				tw:append(host .. ":\t" .. "No bad responses\n");
			end

		end
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		http_response_positive = {}
		http_response_negative = {}
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
	
end

-- Menu GR -> Packets
register_menu("Gruppo9/HTTP Responses", gr_tap, MENU_TOOLS_UNSORTED)