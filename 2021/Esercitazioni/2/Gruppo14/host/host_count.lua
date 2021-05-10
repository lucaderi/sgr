--Per ciascun host riportare 

--Per tutti i protocolli
-- numero di hosts diversi contattati (client)
-- numero di hosts diversi da cui sono stati contattati (server)

local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_tcp_flags  = Field.new("tcp.flags")
local f_tcp_flags_syn  = Field.new("tcp.flags.syn")
local f_tcp_flags_ack  = Field.new("tcp.flags.ack")
local f_udp_src_port = Field.new("udp.srcport")
local f_udp_dst_port = Field.new("udp.dstport")

local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

local function gr_tap()
    -- Declare the window we will use
    local tw = TextWindow.new("Host Counter")

    -- it contains all tcp servers' ip
    local tcp_server = {}
    -- it contains all tcp clients' ip
    local tcp_client = {}

    -- structure containing all information for udp management
    local udp_info = {
        -- it contains all udp servers' ip
        servers = {},
        -- it contains all udp client' ip
        clients = {},

        -- number of elements in servers
        num_srv = 0,
        -- number of elements in clients
        num_cli = 0
    }

    -- this is our tap
    local tap = Listener.new()

    local function remove()
        -- this way we remove the listener that otherwise will remain running indefinitely
        tap:remove()
    end

    -- we tell the window to call the remove() function when closed
    tw:set_atclose(remove)

    -- controls if t contains ip
    function contains(t, ip)

        for _, v in ipairs(t) do
            if v == ip then
                return true
            end
        end

        return false
    end

    -- this function will be called once for each packet
    function tap.packet(pinfo, tvb)

        -- Call the function that extracts the field    
        local ip_src = f_ip_src()
        local ip_dst = f_ip_dst()
        local tcp_flags_syn = f_tcp_flags_syn()
        local tcp_flags_ack = f_tcp_flags_ack()
        local udp_src_port = f_udp_src_port()
        local udp_dst_port = f_udp_dst_port()
        local tcp_flag = f_tcp_flags()
        

        if (ip_src == nil or ip_dst == nil) then return end

        local str_ip_src = getstring(f_ip_src().value)
        local str_ip_dst = getstring(f_ip_dst().value)
        
        --[[ DEBUG
            tw:append(str_ip_src .. "\n")
            tw:append(str_ip_dst .. "\n")  
        --]]

        -- Checks if it's a TCP packet
        if tcp_flag ~= nil then

            syn_flag = tcp_flags_syn.value
            ack_flag = tcp_flags_ack.value

            if syn_flag == true and ack_flag == false then

                if str_ip_src ~= nil and str_ip_dst ~= nil then
                    
                    -- Checks if it's a new TCP client 
                    if contains(tcp_client, str_ip_src) == false then
                        table.insert(tcp_client, str_ip_src)
                    end

                    -- Checks if it's a new TCP client 
                    if contains(tcp_server, str_ip_dst) == false then
                        table.insert(tcp_server, str_ip_dst)
                    end
                end
                
            end

        else
            -- Checks if it's an UDP packet
            if udp_src_port ~= nil and udp_dst_port ~= nil then
                
                -- Checks if it's a new UDP client 
                if udp_info.clients[str_ip_src] == nil then
                    udp_info.clients[str_ip_src] = true

                    -- increase the counter
                    old_value = udp_info.num_cli or 0
                    udp_info.num_cli = old_value + 1
                end
                -- Checks if it's a new UDP server 
                if udp_info.servers[str_ip_dst] == nil then
                    udp_info.servers[str_ip_dst] = true
                    
                    -- increase the counter
                    old_value = udp_info.num_srv or 0
                    udp_info.num_srv = old_value + 1
                end
            end

        end
    end

    -- this function will be called once every few seconds to update our window
    function tap.draw(t)
        tw:clear()

        local n_client = #tcp_client
        local n_server = #tcp_server

        tw:append("Client TCP: \n")

        for k, v in ipairs(tcp_client) do
            tw:append(getstring(k) .. ") " .. v .. "\n")
        end

        tw:append("\nServer TCP: \n")

        for k, v in ipairs(tcp_server) do
            tw:append(getstring(k) .. ") " .. v .. "\n")
        end

        tw:append("\nServer UDP: \n")
        i = 1
        for k, _ in pairs(udp_info.servers) do
            tw:append(getstring(i) .. ") " .. getstring(k) .. "\n")
            i = i + 1
        end

        tw:append("\nClient UDP: \n")
        i = 1
        for k, _ in pairs(udp_info.clients) do
            tw:append(getstring(i) .. ") " .. getstring(k) .. "\n")
            i = i + 1
        end

        tw:append("\n--------------------\n\n")
        tw:append("Client tcp n.: " .. getstring(n_client) .. "\n")
        tw:append("Server tcp n.: " .. getstring(n_server) .. "\n\n")
        
        tw:append("Client udp n.: " .. getstring(udp_info.num_srv) .. "\n")
        tw:append("Server udp n.: " .. getstring(udp_info.num_cli) .. "\n\n")
 
    end

    -- this function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        tw:clear()
        tcp_server = {}
        tcp_client = {}
        udp_info = {
            servers = {},
            clients = {},
            num_srv = 0,
            num_cli = 0
        }
    
    end

    -- Ensure that all existing packets are processed.
    retap_packets()
end

-- Menu GR -> DNS_ratio
register_menu("GR/Host_count", gr_tap, MENU_TOOLS_UNSORTED)