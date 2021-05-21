--[[
    Per ciascun host riportare 
    DNS
    - il rapporto queries fatte/risposte ricevute (in teoria dovrebbe essere intorno a 1)
    - il rapporto risposte positive/risposte con errori
    - numero di queries diverse (nomi al dominio) inviate
--]]

-- Field Extractors
local f_dns_query_name = Field.new("dns.qry.name")
local f_dns_flag_response = Field.new("dns.flags.response")
local f_dns_flag_rcode = Field.new("dns.flags.rcode")
local f_ip_src = Field.new("ip.src")

local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

local function gr_tap()
    -- Declare the window we will use
    local tw = TextWindow.new("DNS queries ratio")

    -- Maximum number of domains to be saved simultaneously
    local DOMAIN_LIMIT = 50

    -- Table of domains where the number of queries and the number of responses are saved for each of them.
    local domains = {}

    -- Number of saved domains 
    local n = 0

    -- this is our tap
    local tap = Listener.new()

    local function remove()
        -- this way we remove the listener that otherwise will remain running indefinitely
        tap:remove()
    end

    -- we tell the window to call the remove() function when closed
    tw:set_atclose(remove)

    --[[ 
        this function will be called every time a domain is entered and n > DOMAIN_LIMIT
        It removes the domain with fewer queries 
    --]]
    local function cut_table(t, f)

        local copy = {}

        for v in pairs(t) do
            -- here we make a copy of the table, but the copy will be an indexed table
            table.insert(copy, v)
        end

        -- sort the indexed table in ascending order
        table.sort(copy, f)
    
        --[[ DEBUG
        for k, v in ipairs(copy) do
            tw:append(string.format(t[v].query) .. " - " .. v .. "\n")
        end
        tw:append("\n--------------\n")
        --]]

        for k, v in ipairs(copy) do
            -- until n > DOMAIN_LIMIT, removes the domain with fewer queries
            if n > DOMAIN_LIMIT - 1 then
                t[v] = nil
                n = n - 1
            else
                break
            end
        end
    end

    -- this function will be called once for each packet
    function tap.packet(pinfo, tvb)

        -- Call the function that extracts the field
        local dns_flag_response = f_dns_flag_response()
        local dns_flag_rcode = f_dns_flag_rcode()
        local ip_src = f_ip_src()

        if ip_src ~= nil and dns_flag_response ~= nil then

            local ip_src_string = getstring(ip_src.value)

            tw:append("IP letto: " .. getstring(ip_src_string) .. " \n")

            if domains[ip_src_string] == nil then  
                
                if n > DOMAIN_LIMIT - 1 then 
                    -- Call the function to remove domains until we come within the limit
                    tw:append("calling cuttable\n")
                    cut_table(domains, function (x, y) return domains[x].query < domains[y].query end)
                end
                -- here we initialise the new domain and increase n
                domains[ip_src_string] = {query = 0, responses = 0, error = 0}
                n = n + 1
            end

            if domains[ip_src_string] ~= nil then

                tw:append("OK, " .. getstring(ip_src_string) .. " \n")

                if dns_flag_response.value == 1 then
                    old_value = domains[ip_src_string].responses or 0 -- read the old value  
                    domains[ip_src_string].responses = old_value + 1 -- increase the number of responses observed for this DNS name

                    if dns_flag_rcode.value > 0 then
                        old_value = domains[ip_src_string].error or 0 -- read the old value  
                        domains[ip_src_string].error = old_value + 1 -- increase the number of responses observed for this DNS name
                    end
                else
                    old_value = domains[ip_src_string].query or 0
                    domains[ip_src_string].query = old_value + 1
                end
            end
        end
    end

    -- this function will be called once every few seconds to update our window
    function tap.draw(t)
        --tw:clear()

        for k, v in pairs(domains) do
            --[[
                for each saved domain we print on screen the name, the number of queries,
                the number of responses and ratio
            --]]
            local query = v.query
            local resp = v.responses
            local err = v.error

            tw:append("Domain: " .. k .. "\n");
            tw:append("Query n.: " .. getstring(query) .. "\n")
            tw:append("Response n.: " .. getstring(resp) .. "\n")
            tw:append("Error n.: " .. getstring(err) .. "\n")

            if resp ~= 0 then
                ratio1 = query / resp
            else
                ratio1 = 0
            end
            
            if err ~= 0 then
                ratio2 = resp / err
            else
                ratio2 = 0
            end
            
            tw:append("Query/Positive responses ratio: " .. getstring(ratio1) .. "\n")
            tw:append("Positive responses/Responses with error ratio: " .. getstring(ratio2) .. "\n-----------\n")
        end

        tw:append("Total number of domains: " .. getstring(n))
    end

    -- this function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        tw:clear()
        domains = {}
        n = 0
    end

    -- Ensure that all existing packets are processed.
    retap_packets()
end

-- Menu GR -> DNS_ratio
register_menu("GR/DNS_ratio", gr_tap, MENU_TOOLS_UNSORTED)