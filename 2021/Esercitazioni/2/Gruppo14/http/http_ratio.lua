-- Field Extractors
local f_http_response = Field.new("http.response")
local f_http_response_code = Field.new("http.response.code")
local f_ip_src = Field.new("ip.src")

local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

local function gr_tap()
    -- Declare the window we will use
    local tw = TextWindow.new("HTTP response ratio")

    -- Maximum number of queries to be saved simultaneously
    local QUERIES_LIMIT = 20

    -- Table of queries where the number of positive and negative responses are saved for each of them.
    local queries = {}

    -- Number of queries 
    local n = 0

    -- this is our tap
    local tap = Listener.new();

    local function remove()
        -- this way we remove the listener that otherwise will remain running indefinitely
        tap:remove()
    end

    -- we tell the window to call the remove() function when closed
    tw:set_atclose(remove)

    --[[ 
        this function will be called every time a query is entered and n > QUERY_LIMIT
        It removes the query with fewer responses 
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
            tw:append(v)
            tw:append(", pos = " .. string.format(t[v].positive_resp))
            tw:append(", neg = " .. string.format(t[v].negative_resp) .. "\n")
        end 
        tw:append("\n--------------\n")
        --]]

        for k, v in ipairs(copy) do
            -- until n > QUERY_LIMIT - 1, removes the query with fewer responses
            if n > QUERIES_LIMIT - 1 then
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
        local http_response = f_http_response()
        local code_val = f_http_response_code()
        local ip_src = f_ip_src()

        -- convert ip address to string
        local ip_src_string = getstring(ip_src)

        if (http_response ~= nil) then

            local response = http_response.value

            --[[ DEBUG
            tw:append("http_response = " .. getstring(response))
            tw:append("\nhttp_response_value = " .. getstring(code_val))
            --]]

            if ip_src_string ~= nil then 
                --[[ DEBUG
                tw:append("\nhttp_request_uri = " .. ip_src_string)
                tw:append("\n---------------\n")
                --]]

                if queries[ip_src_string] == nil then

                    if n > QUERIES_LIMIT - 1 then 
                        -- Call the function to remove queries until we come within the limit
                        cut_table(queries, function (x, y) return (queries[x].positive_resp + queries[x].negative_resp) < (queries[y].positive_resp + queries[y].negative_resp) end)
                    end
                
                    -- here we initialise the new query and increase n
                    queries[ip_src_string] = {positive_resp = 0, negative_resp = 0}
                    n = n + 1
                end

                -- we are only interested in the responses
                if queries[ip_src_string] ~= nil and response then 

                    if code_val.value >= 200 and code_val.value <= 299 then

                        old_value = queries[ip_src_string].positive_resp or 0 -- read the old value  
                        queries[ip_src_string].positive_resp = old_value + 1 -- increase the number of positive responses from that host

                    elseif code_val.value >= 500 and code_val.value <= 599 then

                        old_value = queries[ip_src_string].negative_resp or 0
                        queries[ip_src_string].negative_resp = old_value + 1
                    end 
                end
            end
        end
    end

    -- this function will be called once every few seconds to update our window
    function tap.draw(t)
        --tw:clear()
        
        for k, v in pairs(queries) do
            --[[
                for each saved domain we print on screen the hostname, 
                the number of positive (and negative) responsers and ratio
            --]]
            local positive = v.positive_resp
            local negative = v.negative_resp

            tw:append("Host: " .. k .. "\n");
            tw:append("Positive n.: " .. string.format(positive) .. "\n")
            tw:append("Negative n.: " .. string.format(negative) .. "\n")

            if negative ~= 0 then
                ratio = positive / negative
            else
                ratio = 0
            end

            tw:append("Ratio: " .. ratio .. "\n-----------\n")
        end

    end

    -- this function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        tw:clear()
        queries = {}
        n = 0
    end

    -- Ensure that all existing packets are processed.
    retap_packets()

end
-- Menu GR -> HTTP_ratio
register_menu("GR/HTTP_ratio", gr_tap, MENU_TOOLS_UNSORTED)