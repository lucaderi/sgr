-- bisogna aggiungere il contenuto del layer stun al payload
-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


local f_type_message = Field.new("stun.type")
local f_stun_length = Field.new("stun.length")
local f_stun_username =  Field.new("stun.att.username")
local f_stun_network_id = Field.new("stun.att.google.network_id")
local f_stun_network_cost = Field.new("stun.att.google.network_cost")
local f_stun_unknown_att = Field.new("stun.unknown_attribute")
local f_stun_trasp = Field.new("stun.att.transp")
local f_stun_realm = Field.new("stun.att.realm")
local f_stun_nonce = Field.new("stun.att.nonce")
local f_stun_software = Field.new("stun.att.software")
local f_stun_ip_xor = Field.new("stun.att.ipv4-xord")
local f_stun_ms_version = Field.new("stun.att.ms.version")
local f_stun_ms_version_ice = Field.new("stun.att.ms.version.ice")
local f_stun_ms_qs = Field.new("stun.att.ms.service_quality")
local f_stun_ms_st = Field.new("stun.att.ms.stream_type")
local f_udp_traffic = Field.new("udp")
local f_udp_payload = Field.new("udp.length")
local f_src_ip = Field.new("ip.src")
local f_dst_ip = Field.new("ip.dst")
local f_src_port = Field.new("udp.srcport")
local f_dst_port = Field.new("udp.dstport")




local function riconoscitore ()

   local window = TextWindow.new("Flow of non standard protocol")

   local tap = Listener.new("udp")

    local function remove_Tap()
        tap:remove()
     end

   window:set_atclose(remove_Tap)

    local whatsapp_tab = {}
    local telegram_tab = {}
    local teams_tab = {}

--##################################################

local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

--##################################################

local function safe_check(tab)
    local ok, val = pcall(next,tab)
    if not ok then val = false end
    return val
end

--##################################################

local function safe_pairs(tab)
    if type(tab) == "table" then
        return pairs(tab)
    end
    return pairs({})
end

--##################################################

local function exists(tab,val)
    for _, elem in ipairs(tab) do
        if elem == val then return true end
    end
    return false
end

--##################################################

local function find_flow(key,tab_w,tab_tel,tab_tea)
    if tab_w[key] ~= nil then return tab_w
    elseif tab_tel[key] ~= nil then return tab_tel
    elseif tab_tea[key] ~= nil then return tab_tea
    end
end


--##################################################

local function develop_table(tab,src,src_port,dst,dst_port,payload,info,protocol)
    info = info or "unknown"
    protocol = protocol or "unknown"
    local key = src..":"..src_port.." <--> "..dst..":"..dst_port
    if tab[key]== nil then
        local key2 = dst..":"..dst_port.." <--> "..src..":"..src_port
        if tab[key2] == nil  then
            tab[key] ={Protocol = protocol, Info ={}, Payload = payload,  Count = 1}
            table.insert(tab[key]["Info"],info)
        else
            key = key2
        end
    end
    tab[key]["Payload"] = tab[key]["Payload"] + payload
    tab[key]["Count"] = tab[key]["Count"] + 1
    if not exists(tab[key]["Info"],info) then table.insert(tab[key]["Info"],info) end
end

--##################################################

local function processPackets(tab_w,tab_tel,tab_tea)
    local udp_traffic = f_udp_traffic()
    local src = getstring(f_src_ip())
    local dst = getstring(f_dst_ip())
    local src_port = getstring(f_src_port())
    local dst_port = getstring(f_dst_port())
    local udp_payload = getstring(f_udp_payload())
    local type_message = getstring(f_type_message())
    local stun_length = getstring(f_stun_length())
    local stun_username = f_stun_username()
    local stun_network_id = f_stun_network_id()
    local stun_network_cost = f_stun_network_cost()
    local stun_unknown_att = f_stun_unknown_att()
    local stun_trasp = f_stun_trasp()
    local stun_realm = f_stun_realm()
    local stun_nonce = f_stun_nonce()
    local stun_software = f_stun_software()
    local stun_ip_xor = f_stun_ip_xor()
    local stun_ms_version = f_stun_ms_version()
    local stun_ms_version_ice = f_stun_ms_version_ice()
    local stun_ms_qs = f_stun_ms_qs()
    local stun_ms_st = f_stun_ms_st()
    local info = ""
    local protocol = ""

    if udp_traffic then
        -- Data Indication
        if type_message == "0x0017" then 
            info = "Data Indication "
            protocol = "Telegram"
        
        -- Send Data
        elseif  type_message == "0x0016" then
            info = "Send Data"
            protocol = "Telegram"

        -- Create Permission Request
        elseif type_message == "0x0008" then
            info = "Create Permission Request"
            protocol = "Telegram"

        -- Create Permission Response
        elseif type_message == "0x0108" then
            info = "Create Permission Response"
            protocol = "Telegram"
        
        -- Refresh request
        elseif type_message == "0x0004" then
            info = "Refresh Request"
            
            if stun_ms_version and stun_username then
                protocol = "Teams"
            elseif stun_username then
                protocol = "Telegram"
            end
        
        -- Refresh Success Response
        elseif type_message == "0x0104" then
            info = "Refresh Success Response"
            protocol = "Telegram"
        
        -- unknown request whatsapp
        elseif type_message == "0x0800" then
            info = "unknown request"
            protocol = "Whatsapp"

        -- binding request   
        elseif type_message == "0x0001" then
            info = "Binding Request"
             
            if stun_username and stun_unknown_att then
                protocol = "Teams"
            elseif stun_network_id and stun_network_cost and stun_username then 
                protocol = "Telegram"    
            elseif stun_length == "0" then
                protocol = "Telegram"
            else
                protocol = "Whatsapp"
            end
        
        -- allocate request
        elseif type_message == "0x0003" then

            if stun_ms_version then
                protocol = "Teams"
                if stun_nonce and stun_realm then
                    info = "Allocate Request bandwindth with nonce and realm"
                else
                    info = "Allocate Request bandwindth"
                end
            
            elseif stun_unknown_att then 
                info = "Allocate Request"
                protocol = "Whatsapp"

            elseif stun_realm and stun_nonce and stun_username then 
                info = "Allocate Request UDP User"
                protocol = "Telegram"

            elseif stun_trasp == "0x11" then 
                info = "Allocate Request UDP"
                protocol = "Telegram"
            end

        -- binding success response
        elseif type_message == "0x0101" then
            info = "Binding Success Response"
           
            if stun_ms_version_ice then 
                protocol = "Teams"

            elseif stun_software then 
                protocol = "Telegram"

            elseif (not stun_software) and stun_ip_xor then 
                protocol = "Telegram"
            else
                protocol = "Whatsapp"

            end

        -- Allocate Success Response
        elseif type_message == "0x0103" then
            info = "Allocate Success Response"
            if stun_ms_version  then
                protocol = "Teams"
            elseif stun_software then
                protocol = "Telegram"
            else
                protocol = "Whatsapp"
            end

        elseif type_message == "0x0113"  then
            info = "Allocate Error Response error code : 401"
            if stun_ms_version then
                protocol = "Teams"
            elseif stun_realm then 
                protocol = "Telegram"
            end
        else
            local key1 = src..":"..src_port.." <--> "..dst..":"..dst_port
            local key2 = dst..":"..dst_port.." <--> "..src..":"..src_port
            if tab_w[key1] ~= nil or tab_tel[key1] ~= nil or tab_tea[key1] ~= nil then
                develop_table(find_flow(key1,tab_w,tab_tel,tab_tea),src,src_port,dst,dst_port,udp_payload)
            elseif tab_w[key2]~= nil  or tab_tel[key2]~= nil  or tab_tea[key2]~= nil  then
                develop_table(find_flow(key2,tab_w,tab_tel,tab_tea),src,src_port,dst,dst_port,udp_payload)
            end
        end
        print("eccoli "..getstring(stun_ms_version_ice))
        print(src..":"..src_port.. " e "..dst..":"..dst_port.." "..protocol.." "..info)
        if protocol == "Whatsapp" then
            develop_table(tab_w,src,src_port,dst,dst_port,udp_payload,info,protocol)
        elseif protocol == "Telegram"  then
            develop_table(tab_tel,src,src_port,dst,dst_port,udp_payload,info,protocol)
        elseif protocol == "Teams" then
            develop_table(tab_tea,src,src_port,dst,dst_port,udp_payload,info,protocol)
        end

        return tab_w,tab_tel,tab_tea
    end
end

--##################################################

    local function print_risultato(whatsapp_tab,telegram_tab,teams_tab)
        if safe_check(whatsapp_tab) then 
        window:append("\t\t\t\t~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ PACKED UNDER WHATSAPP ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
            for flow,elem in safe_pairs(whatsapp_tab) do
                print(whatsapp_tab)
                print(flow.." "..elem.Protocol)
                window:append(flow.."\t\tProtocol: "..elem["Protocol"].."\t\tBytes trasferiti: "..elem["Payload"].."\t\tNumero di pachetti: "..elem["Count"].."\n\n")
            end
        end
        if safe_check(telegram_tab) then 
            window:append("\t\t\t\t~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ PACKED UNDER TELEGRAM ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
            for flow,elem in safe_pairs(telegram_tab) do
                print(flow.." "..elem.Protocol)
                window:append(flow.."\t\tProtocol: "..elem["Protocol"].."\t\tBytes trasferiti: "..elem["Payload"].."\t\tNumero di pachetti: "..elem["Count"].."\n\n")
            end
        end
        if safe_check(teams_tab) then
            window:append("\t\t\t\t~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ PACKED UNDER TEAMS ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
            for flow,elem in safe_pairs(teams_tab) do
                print(flow.." "..elem.Protocol)
                window:append(flow.."\t\tProtocol: "..elem["Protocol"].."\t\tBytes trasferiti: "..elem["Payload"].."\t\tNumero di pachetti: "..elem["Count"].."\n\n")
            end
        end
    end

--##################################################

    function  tap.packet(pinfo,tvb)
        whatsapp_tab,telegram_tab,teams_tab = processPackets(whatsapp_tab,telegram_tab,teams_tab)
    end

    function tap.draw()
        print("draw inizio chiamata")
        window:clear()
        print_risultato(whatsapp_tab,telegram_tab,teams_tab)
        print("draw fine chiamata")
    end

    function tap.reset()
        whatsapp_tab = {}
        telegram_tab = {}
        teams_tab = {}
        print("Reset effettuato")
    end

    retap_packets()

end


register_menu("NON STANDARD PROTOCOL",riconoscitore,MENU_TOOLS_UNSORTED)