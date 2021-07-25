--[[
    Titolo: Plugin wireshark per la rilevazione di crypto locker

    - prendete https://github.com/ntop/nDPI/tree/dev/wireshark/tshark che vi permette di usare wireshark per fare il 
    parsing dei pacchetti
    oppure
    - potete fare il solito plugin per wireshark che vi ho mostrato a lezione

    Scaricatevi
    http://www.protectus.com/download/files/cryptoshield.pcapng

    In questo pcap c’e’ un crypto locker che si identifica facilmente dato che gli host via SMB 
    (la condivisione di windows) prevalentemente leggono files, a volte cancellano, a volte li creano.

    Se filtrate con "smb.share.access.write == 1” trovate i files creati.

    Quello che vi chiedo e’ di fare un report dove per host (indirizzo IP) sono elencati il numero di files 
    creati (quindi write in scrittura) vs quelli letti vs il resto (es rinomina, cancella) e che mi impostate 
    un semplice algoritmo dove si evidenziano host anomali quando c’e’ una distribuzione inaspettata di operazioni sui files.

    Come referenza potete far riferimento a 
    https://www.protectus.com/blog/may2017/ransomware_identification_using_network_traffic.pdf
--]]

-- Packets fields we need to use for this tool
local f_ip_dst = Field.new("ip.dst")
local f_ip_src = Field.new("ip.src")
local f_tcp_dstport = Field.new("tcp.dstport")
local f_tcp_srcport = Field.new("tcp.srcport")
local f_smb2_cmd = Field.new("smb2.cmd")
local f_smb2_create_action = Field.new("smb2.create.action")
local f_smb2_create_disposition = Field.new("smb2.create.disposition")
local f_smb2_file_disposition_info = Field.new("smb2.file_disposition_info")
local f_smb2_file_rename_info = Field.new("smb2.file_rename_info")
local f_smb2_flags_response = Field.new("smb2.flags.response")
local f_smb2_nt_status = Field.new("smb2.nt_status")
local f_smb2_file_info_infolevel = Field.new("smb2.file_info.infolevel")

-- Function used to convert anything to a string
local function getstring(finfo)
    
    local ok, val = pcall(tostring, finfo)
    if not ok then 
        val = "(unknown)"
    end
    return val
end


local function gr_tap()
    -- Declare the window we will use
    local tw = TextWindow.new("Criptolocker Analizer")

    local tap = Listener.new()

    local function remove()

        tap:remove()
    end

    tw:set_atclose(remove)

    -- Codes that represent the detected risk of cryptolocker
    Anomaly_code = {
        
        RISK_CODE = 2,
        POTENTIAL_RISK_CODE = 1,
        NO_RISK_CODE = 0
    }

    -- Codes of CreateAction field in the create response packet
    Create_action_values = {

        FILE_SUPERSEDED = 0,
        FILE_OPENED = 1,
        FILE_CREATED = 2,
        FILE_OVERWRITTEN = 3
    }

    -- Codes of CreateDisposition field in the create request packet
    Create_disposition_values = {

        FILE_SUPERSEDE = 0,
        FILE_OPEN = 1,
        FILE_CREATE = 2,
        FILE_OPEN_IF = 3,
        FILE_OVERWRITE = 4,
        FILE_OVERWRITE_IF = 5
    }
    
    -- Structure used to map an ip address of a host to its collected data
    local host_info = {}

    -- Function that implements the algorithm to detect the presence of cryptolocker
    --[[
    local function anomaly_checker()
        
        TODO: IMPLEMENT
    end
    ]]--
    
    -- Function that increments a given value
    local function increment_value(value)
        
        old_value = value or 0
        value = old_value + 1
        return value
    end

    --Function that, depending on the create_action field of a packet, increases the number of successes of the appropriate field
    local function create_action_analyzer(ip_string)

        local smb2_create_action = f_smb2_create_action()
        local v = smb2_create_action.value

        if v == Create_action_values.FILE_SUPERSEDED then 

            host_info[ip_string].superseded.count = increment_value(host_info[ip_string].superseded.count)
            host_info[ip_string].superseded.succ = increment_value(host_info[ip_string].superseded.succ)
            
        elseif v == Create_action_values.FILE_OPENED then

            host_info[ip_string].open.count = increment_value(host_info[ip_string].open.count)
            host_info[ip_string].open.succ = increment_value(host_info[ip_string].open.succ)

        elseif v == Create_action_values.FILE_CREATED then

            host_info[ip_string].create.count = increment_value(host_info[ip_string].create.count)
            host_info[ip_string].create.succ = increment_value(host_info[ip_string].create.succ)

        elseif v == Create_action_values.FILE_OVERWRITTEN then

            host_info[ip_string].overwrite.count = increment_value(host_info[ip_string].overwrite.count)
            host_info[ip_string].overwrite.succ = increment_value(host_info[ip_string].overwrite.succ)
        end
    end

    -- Function that, depending on the create_disposition field of a packet, increases the number of failures of the appropriate field
    local function create_disposition_analyzer(ip_string)
       
        local last_create_disposition = host_info[ip_string].last_create_disposition
                        
        if last_create_disposition == Create_disposition_values.FILE_SUPERSEDE then

            host_info[ip_string].superseded.count = increment_value(host_info[ip_string].superseded.count)
            host_info[ip_string].superseded.fail = increment_value(host_info[ip_string].superseded.fail)
            
        elseif last_create_disposition == Create_disposition_values.FILE_OPEN or
                last_create_disposition == Create_disposition_values.FILE_OPEN_IF then

            host_info[ip_string].open.count = increment_value(host_info[ip_string].open.count)
            host_info[ip_string].open.fail = increment_value(host_info[ip_string].open.fail)

        elseif last_create_disposition == Create_disposition_values.FILE_CREATE then

            host_info[ip_string].create.count = increment_value(host_info[ip_string].create.count)
            host_info[ip_string].create.fail = increment_value(host_info[ip_string].create.fail)

        elseif last_create_disposition == Create_disposition_values.FILE_OVERWRITE or
                last_create_disposition == Create_disposition_values.FILE_OVERWRITE_IF then

            host_info[ip_string].overwrite.count = increment_value(host_info[ip_string].overwrite.count)
            host_info[ip_string].overwrite.fail = increment_value(host_info[ip_string].overwrite.fail)
        end

        
    end

    -- Function that initialize the host info structure for a new ip address
    local function init_host(ip_string)

        if host_info[ip_string] == nil then

            host_info[ip_string] = {    create = {count = 0, succ = 0, fail = 0}, 
                                        open = {count = 0, succ = 0, fail = 0}, 
                                        superseded = {count = 0, succ = 0, fail = 0}, 
                                        overwrite = {count = 0, succ = 0, fail = 0},
                                        last_create_disposition = -1,
                                        read = {count = 0, succ = 0, fail = 0},  
                                        delete = {count = 0, succ = 0, fail = 0},  
                                        write = {count = 0, succ = 0, fail = 0},  
                                        rename = {count = 0, succ = 0, fail = 0},
                                        anomalyCode = Anomaly_code.NO_RISK_CODE,
                                    }
        end
    end

    -- Function used to analyze a packet, it's called for each packet
    function tap.packet(pinfo, tvb)
        
        local ip_dst = f_ip_dst()
        local ip_src = f_ip_src()
        local ip_dst_string = getstring(ip_dst)
        local ip_src_string = getstring(ip_src)
        local tcp_dstport = f_tcp_dstport()
        local tcp_srcport = f_tcp_srcport()
        local smb2_cmd = f_smb2_cmd()


        if ip_src_string ~= nil and ip_dst_string ~= nil and tcp_dstport ~= nil and (tcp_dstport.value == 445 or tcp_srcport.value == 445) and smb2_cmd ~= nil then 
         
            local file_disposition_info = f_smb2_file_disposition_info()
            local file_rename_info = f_smb2_file_rename_info()
            local smb2_flags_response = f_smb2_flags_response()
            local smb2_create_disposition = f_smb2_create_disposition()
            local command = smb2_cmd.value

            if smb2_flags_response.value == false then -- request packet
                
                init_host(ip_src_string)
                
                if command == 5 then -- open/create command

                    --[[ 
                        we save for the current host the information on its last disposition used in a request in order to be able, 
                        at the time of checking the reply packet, to understand if the latter create command 
                        refers to a create, open, overwrite or supersed command
                     --]]
                    local v = smb2_create_disposition.value
                    host_info[ip_src_string].last_create_disposition = v
                end
    
                if command == 8 then    -- read command
                    host_info[ip_src_string].read.count = increment_value(host_info[ip_src_string].read.count)
                end
    
                if command == 9 then    -- write command
                    host_info[ip_src_string].write.count = increment_value(host_info[ip_src_string].write.count)
                end
    
                if command == 17 then   -- setinfo command (used for delete/rename operations)
    
                    if file_rename_info ~= nil then     -- if the field is present then the operation is a rename 
                        host_info[ip_src_string].rename.count = increment_value(host_info[ip_src_string].rename.count)
                        
                    elseif file_disposition_info ~= nil then -- if the field is present then the operation is a delete
                        host_info[ip_src_string].delete.count = increment_value(host_info[ip_src_string].delete.count)
                    end
                end

            else --response packet

                init_host(ip_dst_string)

                local smb2_nt_status = f_smb2_nt_status()

                if smb2_nt_status ~= nil then

                    if command == 5 then -- open/create | NT_status = 2 -> file not found
                        -- If nt_status is != 0 the operation has terminated with error
                        if smb2_nt_status.value == 0 then
                            create_action_analyzer(ip_dst_string)
                        else 
                            create_disposition_analyzer(ip_dst_string)
                        end
                        
                    elseif command == 8 then -- read command
                        -- If nt_status is != 0 the operation has terminated with error
                        if smb2_nt_status.value == 0 then
                            host_info[ip_dst_string].read.succ = increment_value(host_info[ip_dst_string].read.succ)
                        else
                            host_info[ip_dst_string].read.fail = increment_value(host_info[ip_dst_string].read.fail)
                        end
    
                    elseif command == 9 then -- write command
                        -- If nt_status is != 0 the operation has terminated with error
                        if smb2_nt_status.value == 0 then
                            host_info[ip_dst_string].write.succ = increment_value(host_info[ip_dst_string].write.succ)
                        else
                            host_info[ip_dst_string].write.fail = increment_value(host_info[ip_dst_string].write.fail)
                        end
                    
                    elseif command == 17 then -- setinfo command
                        
                        smb2_file_info_infolevel = f_smb2_file_info_infolevel()
                        
                        if smb2_file_info_infolevel.value == 13 then
                            -- If nt_status is != 0 the operation has terminated with error
                            if smb2_nt_status.value == 0 then
                                host_info[ip_dst_string].delete.succ = increment_value(host_info[ip_dst_string].delete.succ)
                            else
                                host_info[ip_dst_string].delete.fail = increment_value(host_info[ip_dst_string].delete.fail)
                            end
                        end
                    end
                    
                end
            end
        end
    end

    
    -- This function will be called once every few seconds to update our window
    function tap.draw(t)
        
        tw:clear()
        for key, value in pairs(host_info) do
    
            local create = value.create
            local open = value.open
            local superseded = value.superseded
            local overwrite = value.overwrite
            local read = value.read
            local write = value.write
            local delete = value.delete
            local rename = value.rename
            local anomalyCode = value.anomalyCode

            tw:append("IP: " .. key .. "\n")
            tw:append(string.format("CREATE\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", create.count, create.succ, create.fail))
            tw:append(string.format("OPEN\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", open.count, open.succ, open.fail))
            tw:append(string.format("SUPERSEDED\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", superseded.count, superseded.succ, superseded.fail))
            tw:append(string.format("OVERWRITE\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", overwrite.count, overwrite.succ, overwrite.fail))
            tw:append(string.format("READ\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", read.count, read.succ, read.fail))
            tw:append(string.format("WRITE\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", write.count, write.succ, write.fail))
            tw:append(string.format("DELETE\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", delete.count, delete.succ, delete.fail))
            tw:append(string.format("RENAME\trequests: %6d \t| success response: %6d \t| fail response: %6d\n", rename.count, rename.succ, rename.fail))

            tw:append("\n---\n");
        end
    end

    -- This function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        host_info = {}
        tw:clear()
    end

    -- Ensure that all existing packets are processed
    retap_packets()

end

-- Menu GR -> DNS_ratio
register_menu("Project/Analizer", gr_tap, MENU_TOOLS_UNSORTED)