--Per ciascun host riportare 

--DNS
-- il rapporto queries fatte/risposte ricevute (in teoria dovrebbe essere intorno a 1)
-- il rapporto risposte positive/risposte con errori
-- numero di queries diverse (nomi al dominio) inviate

--HTTP
-- Rapporto risposte HTTP positive (es codice 200) e negative (es errori 500)

--Per tutti i protocolli
-- numero di hosts diversi contattattati (client)
-- numero di hosts diversi da cui sono stati contattati (server)


-- display filter to avoid multicast traffic: (not (dst net ff00::/8)) and (not (dst net 224.0.0.0/4))

local f_dns_query_name     = Field.new("dns.qry.name")
local f_dns_flags_response = Field.new("dns.flags.response")
--Field cotaining error code
local f_dns_flags_rcode = Field.new("dns.flags.rcode")

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

function desc(a,b) return (a > b) end

function trimDict(dict, func, limit)

	-- Copy all dictionary keys into an array.
	local a = {}
	local count = 0

	for key, value in pairs(dict) do
		if (value ~= nil) then
			table.insert(a, key)
			count = count + 1
		end
	end

	-- Sort the keys by their values
	table.sort(a, function(x, y) return func(dict[x], dict[y]) end)

	--- @ debug
	print("-----\n")
	print(getstring(count))
	for i,v in ipairs(a) do  
		print(getstring(i) .. "\t".. getstring(v) .. "\t" .. getstring(dict[v]) .. "\n")
	end
	print("----------\n")
	---

	while (count > limit) do
		dict[a[count]] = nil
		count = count - 1
	end

end


local function gr_tap()

	-- Declare the window we will use
	local tw = TextWindow.new("DNS Queries/Answers ratio")

	-- This will contain a hash of counters of appearances of a certain address
	--Queries dictionary
	local dns_queries = {}
	--Answers dictionary
	local dns_answers = {}
	--Dictionaries key:hostname value:counter of error/no error for the answers
	local dns_answers_error = {}
	local dns_answers_no_error = {}

	--number of hostname requested
	local total_dns_hostnames = 0

	--The cap is arbitrary, maybe should sort the dictionaries by occurrences then trim the lowest
	local max_dns_hostnames = 4

	--Keeps track of how many hostname are currently present in the dictionay
	local current_dns_hostnames = 0

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
	
		local dns_query_name = f_dns_query_name() -- Call the function that extracts the field
		local dns_flags_response = f_dns_flags_response()
		local dns_flags_rcode = f_dns_flags_rcode()

		if( dns_query_name == nil  or  dns_flags_response == nil ) then
			return
		end

		--get the string returned by the query name
		dns_query_name = getstring(dns_query_name) 

		--Check if it's a query or an answer (1 bit as a boolean)
		if(dns_flags_response.value) then
			-- DNS answer: bit set to 1.

			--Increase the number of answer for the given hostname entry in the dictionary
			local old_value = dns_answers[dns_query_name] or 0
			dns_answers[dns_query_name] = old_value + 1
			
			-- Check the integer representing the error (0 no error, >0 error)
			if (dns_flags_rcode.value>0) then
				old_value = dns_answers_error[dns_query_name] or 0
				dns_answers_error[dns_query_name] = old_value + 1
			else
				old_value = dns_answers_no_error[dns_query_name] or 0
				dns_answers_no_error[dns_query_name] = old_value + 1
			end

		else
			-- DNS query: bit set to 0.

			-- If it's the first time we contact this host we add
			--	a new entry in the dictionary, checking if we exceed
			--	the max_dns_hostnames limit. If we do, we trim the
			--	half containing the hosts with less packets.
			if(dns_queries[dns_query_name] == nil) then
				
				if( current_dns_hostnames+1 > max_dns_hostnames) then
					trimDict(dns_queries, desc, max_dns_hostnames/2)
					current_dns_hostnames = max_dns_hostnames/2
				end

				total_dns_hostnames = total_dns_hostnames + 1
				current_dns_hostnames = current_dns_hostnames + 1
				dns_queries[dns_query_name] = 0

			end

			-- increase the number of queries observed for this DNS name
			dns_queries[dns_query_name] = dns_queries[dns_query_name] + 1
		
		end
		
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		
		tw:clear()
		for host,num in pairs(dns_queries) do

			--ottengo il numero di risposte per l'host attuale
			local answers = dns_answers[host] or 0
			if(answers>0) then
				--ottengo il numero di errori per l'host attuale
				local errors= dns_answers_error[host] or 0
				local no_errors= dns_answers_no_error[host] or 0

				if (errors>0 and no_errors>0) then
					tw:append(host .. ":\t" .. (num/answers) .. "\t" .. (no_errors/errors) .. "\n");
				end
				if (errors==0 and no_errors>0) then
					tw:append(host .. ":\t" .. (num/answers) .. "\t" .. "No errors" .. "\n");
				end
				if (errors>0 and no_errors==0) then
					tw:append(host .. ":\t" .. (num/answers) .. "\t All the response contains errors (" .. errors .. " errors)" .. "\n");
				end
			else
				tw:append(host .. "\t" .. "No answer received" .. "\n");
			end
		end

		tw:append("\n");
		tw:append("Total hostnames queried: " .. total_dns_hostnames);
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		dns_queries = {}
		dns_answers = {}
		dns_answers_error = {}
		dns_answers_no_error = {}
		total_dns_hostnames = 0
		current_dns_hostnames = 0
	end

	-- Ensure that all existing packets are processed.
	retap_packets()

end

-- Menu GR -> Packets
register_menu("Gruppo9/DNS Q-A ratio", gr_tap, MENU_TOOLS_UNSORTED)
