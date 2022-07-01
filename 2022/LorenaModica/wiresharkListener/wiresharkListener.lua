local hyperloglog = require 'hyperloglog'
local utils = require 'utils'

-- Define the menu entry's callback
local function host_info ()
	
	local function host_func(ipv4_address)
    	
    	local window = TextWindow.new("Host Info")
   
    	if check_ipv4(ipv4_address) then
        
			local estimate_one = 0
			local estimate_two = 0
			
			--contiene coppie host,stima
			local host_packets= {}

       		local hll_hosts = {}
        	local hll_to_host = {}
			--contiene coppie host, hll associata
			local hll_packets = {}
        
        	local init_one = hll_init (hll_hosts , 19)
			local init_two = hll_init (hll_to_host, 19)
			
			if (init_one and init_two) then	

				 -- this is our tap
				local tap = Listener.new();
		    
				local function remove()
					-- this way we remove the listener that otherwise will remain running indefinitely
					tap:remove();
				end
				
				-- we tell the window to call the remove() function when closed
				window:set_atclose(remove)


				-- this function will be called once for each packet
				function tap.packet(pinfo,tvb)
					
					local src = tostring(pinfo.src)
					local dst = tostring(pinfo.dst)	
					local host = nil
						
								
					if dst == ipv4_address then
						
						--hll conta numero di volte in cui ipv4_address e' stato
						--contattato
						hll_add(hll_hosts,src)
						estimate_one=hll_count(hll_hosts)
										
						host=src
						
					elseif src == ipv4_address then  
						
						--hll conta numero host diversi contattati da ipv4_address
						hll_add(hll_to_host,dst)
						estimate_two=hll_count(hll_to_host)
						
						host=dst
	
					end

					if host then
			
						if 	host_packets[host] == nil then
							hll_packets[host]={}
							if hll_init(hll_packets[host],19) then
								host_packets[host]= 0
							end
						end	
						
						hll_add(hll_packets[host],tostring(tvb))
						host_packets[host]=hll_count(hll_packets[host]) 
					end	
					
				end
					
				-- this function will be called once every few seconds to update our window
				function tap.draw(t)
					window:clear()
		
					local message = string.format("Info about host: %s \n",ipv4_address)
			   		window:set(message)
					window:append("\nEstimated of how many times " .. ipv4_address .. 
								  		" has been contacted from different hosts : " .. 
										estimate_one .."\n"  )
					window:append("\nEstimated different hosts contacted by " .. ipv4_address .." : " .. estimate_two .."\n" )
					
					window:append("\nEstimated packets per host:\n" )
					for ip,num in pairs(host_packets) do
						window:append(ip .. ":\t" .. num .. "\n");
					end					

				end
				
				-- this function will be called whenever a reset is needed
				-- e.g. when reloading the capture file
				function tap.reset()
					window:clear()
					host_packets={}
					hll_packets={}
					init_one = hll_reset (hll_hosts)
					init_two = hll_reset (hll_to_host)
					estimate_one=0
					estimate_two=0	
				end
					
				-- Ensure that all existing packets are processed.
				retap_packets()	
			end
        else
       		local message = string.format("ERROR: %s : please insert a valid ipv4 address!",ipv4_address);
        	window:set(message);
        end
        
    end

    new_dialog("Host Info",host_func,"Host address")
    	
end

-- Create the menu entry
register_menu("Host info/Host stats",host_info,MENU_TOOLS_UNSORTED)

-- Notify the user that the menu was created
if gui_enabled() then
	local splash = TextWindow.new("Hello!");
	splash:set("Wireshark has been enhanced with a new feature.\n")
    splash:append("Go to Tools -> Host info -> Host stats and check it out!")
end

