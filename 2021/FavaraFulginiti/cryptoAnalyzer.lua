-- Packets fields we need to use for this tool
local f_ip_dst = Field.new("ip.dst")
local f_ip_src = Field.new("ip.src")
local f_tcp_dstport = Field.new("tcp.dstport")
local f_tcp_srcport = Field.new("tcp.srcport")
local f_smb2 = Field.new("smb2")
local f_smb2_cmd = Field.new("smb2.cmd")
local f_smb2_create_action = Field.new("smb2.create.action")
local f_smb2_create_disposition = Field.new("smb2.create.disposition")
local f_smb2_file_disposition_info = Field.new("smb2.file_disposition_info")
local f_smb2_file_rename_info = Field.new("smb2.file_rename_info")
local f_smb2_flags_response = Field.new("smb2.flags.response")
local f_smb2_nt_status = Field.new("smb2.nt_status")
local f_smb2_file_info_infolevel = Field.new("smb2.file_info.infolevel")
local f_tcp_analysis_retransmission = Field.new("tcp.analysis.retransmission")


local SEPARATOR = "\t<->\t" -- Used for formatting output prints

function table.is_empty(t)
    -- The next function is used to iterate over the fields of a table.
    -- If the given argument to the next function is an empty table then
    -- a nil value it will be returned.  
    return next(t) == nil  
end

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
    local tw = TextWindow.new("Cryptolocker Analyzer")

    local tap = Listener.new()

    local function remove()
        tap:remove()
    end

    tw:set_atclose(remove)

    -- Codes that represent the detected risk of cryptolocker
    local Anomaly_code = {
        RISK_CODE = 2,
        POTENTIAL_RISK_CODE = 1,
        NO_RISK_CODE = 0
    }

    -- Codes of CreateAction field in the create response packet
    local Create_action_values = {
        FILE_SUPERSEDED = 0,
        FILE_OPENED = 1,
        FILE_CREATED = 2,
        FILE_OVERWRITTEN = 3
    }

    -- Codes of CreateDisposition field in the create request packet
    local Create_disposition_values = {
        FILE_SUPERSEDE = 0,
        FILE_OPEN = 1,
        FILE_CREATE = 2,
        FILE_OPEN_IF = 3,
        FILE_OVERWRITE = 4,
        FILE_OVERWRITE_IF = 5
    }

    local Commands_values = {
        OPEN_CREATE = 5,
        READ = 8,
        WRITE = 9,
        SETINFO = 17
    }
    
    -- Structure used to map an ip address of a host to its collected data
    local host_info = {}
    local count = 0

    -- Function that implements the algorithm to detect the presence of cryptolocker
    local function anomaly_checker()
        
        local RISK_THRESHOLD = 0.70
        local POTENTIAL_RISK_THRESHOLD = 0.35
        local PERC_CREATE_OPEN_RISK_THRESHOLD = 95

        for key, value in pairs(host_info) do
            
            value.risk = Anomaly_code.NO_RISK_CODE
            
            -- If there are little data it returns no risk
            if value.read.count < 10 and value.write.count < 10 and value.delete.count < 10 and value.create.count < 10 and value.open.fail < 10 then
                return
            end
            
            if value.create.count > value.open.fail then
                perc_c_o = (100 * value.open.fail) / value.create.count
            else
                perc_c_o = (100 * value.create.count) / value.open.fail
            end

            if value.read.count > value.write.count then
                perc_r_w = (100 * value.write.count) / value.read.count
            else
                perc_r_w = (100 * value.read.count) / value.write.count
            end

            if value.read.count > value.delete.count then
                perc_r_d = (100 * value.delete.count) / value.read.count
            else
                perc_r_d = (100 * value.read.count) / value.delete.count
            end

            -- Estimates the risk based on the calculated percentages 
            if perc_r_w >= RISK_THRESHOLD and perc_r_d >= RISK_THRESHOLD then
                value.risk = Anomaly_code.RISK_CODE
            elseif (perc_r_w >= RISK_THRESHOLD or perc_r_d >= RISK_THRESHOLD) and perc_c_o >= PERC_CREATE_OPEN_RISK_THRESHOLD then
                value.risk = Anomaly_code.RISK_CODE
            elseif perc_r_w >= POTENTIAL_RISK_THRESHOLD and perc_r_d >= POTENTIAL_RISK_THRESHOLD then
                value.risk = Anomaly_code.POTENTIAL_RISK_CODE
            elseif (perc_r_w >= POTENTIAL_RISK_THRESHOLD or perc_r_d >= POTENTIAL_RISK_THRESHOLD) and perc_c_o >= PERC_CREATE_OPEN_RISK_THRESHOLD then
                value.risk = Anomaly_code.POTENTIAL_RISK_CODE
            end
        end
    end
    
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

            host_info[ip_string] = {
                create      = {count = 0, succ = 0, fail = 0}, 
                open        = {count = 0, succ = 0, fail = 0}, 
                superseded  = {count = 0, succ = 0, fail = 0}, 
                overwrite   = {count = 0, succ = 0, fail = 0},
                read        = {count = 0, succ = 0, fail = 0},  
                delete      = {count = 0, succ = 0, fail = 0},  
                write       = {count = 0, succ = 0, fail = 0},  
                rename      = {count = 0, succ = 0, fail = 0},
                anomalyCode = Anomaly_code.NO_RISK_CODE,
                last_create_disposition = -1,
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
        local smb2_cmd = { f_smb2_cmd() }
        local smb2 = f_smb2()

        local retrasmission = f_tcp_analysis_retransmission()
        
        if retrasmission then 
            return 
        end
        
        if ip_src_string ~= nil and ip_dst_string ~= nil and tcp_dstport ~= nil and smb2 ~= nil then 
         
            local file_disposition_info = { f_smb2_file_disposition_info() }
            local file_rename_info = { f_smb2_file_rename_info() }
            local smb2_flags_response = { f_smb2_flags_response() }
            local smb2_create_disposition = { f_smb2_create_disposition() }

            local command = { f_smb2_cmd() }

            -- We use different index for each packet field because same packet can contain
            -- more than one command (each one with its header and payload). In that case, if a field
            -- is present in more than one command in the package, then the Field extractor returns an 
            -- array/table of values. Since the index used in the command values table is not linked to 
            -- the index of the tables returned for the other fields, then a different index must 
            -- be used for each.
            local disp_info_count = 1
            local ren_count = 1
            local resp_count = 1
            local info_lv_count = 1
            local create_disp_count = 1
            
            for i,com in ipairs(command) do
                if smb2_flags_response[i].value == false then -- request packet

                    local ip_src_dst = ip_src_string .. SEPARATOR .. ip_dst_string
                
                    init_host(ip_src_dst)

                    if com.value == Commands_values.OPEN_CREATE then -- open/create command
    
                        --[[ 
                            we save for the current host the information on its last disposition used in a request in order to be able, 
                            at the time of checking the reply packet, to understand if the latter create command 
                            refers to a create, open, overwrite or supersed command
                         --]]
                        local v = smb2_create_disposition[create_disp_count].value
                        host_info[ip_src_dst].last_create_disposition = v
                        create_disp_count = increment_value(create_disp_count)
                    end
        
                    if com.value == Commands_values.READ then    -- read command -> we increase the read counter
                        host_info[ip_src_dst].read.count = increment_value(host_info[ip_src_dst].read.count)
                    end
        
                    if com.value == Commands_values.WRITE then    -- write command -> we increase the write counter
                        host_info[ip_src_dst].write.count = increment_value(host_info[ip_src_dst].write.count)
                    end
        
                    if com.value == Commands_values.SETINFO then   -- setinfo command (used for delete/rename operations)
        
                        if file_rename_info[ren_count] ~= nil then     
                            -- if the field is present then the operation is a rename, so we increase 
                            -- the rename counter (and the index used to scroll through the redenomination values)
                            host_info[ip_src_dst].rename.count = increment_value(host_info[ip_src_dst].rename.count)
                            ren_count = increment_value(ren_count)
                            
                        elseif file_disposition_info[disp_info_count] ~= nil then
                            -- if the field is present then the operation is a delete, so we increase 
                            -- the delete counter (and the index used to scroll through field values)
                            host_info[ip_src_dst].delete.count = increment_value(host_info[ip_src_dst].delete.count)
                            disp_info_count = increment_value(disp_info_count)
                        end
                    end
    
                else --response packet

                    local ip_dst_src = ip_dst_string .. SEPARATOR .. ip_src_string
    
                    init_host(ip_dst_src)
    
                    local smb2_nt_status = { f_smb2_nt_status() }
    
                    if smb2_nt_status[i] ~= nil then
    
                        if com.value == Commands_values.OPEN_CREATE then -- open/create
                            
                            if smb2_nt_status[i].value == 0 then
                                -- call the function to check the packet's Create_Action field 
                                -- to see which operation has been completed successfully
                                create_action_analyzer(ip_dst_src)
                            else 
                                -- If nt_status is != 0 the operation has terminated with error so we call the
                                -- function that will increment the appropriate failure counter according to 
                                -- the operation that was done in the request package
                                create_disposition_analyzer(ip_dst_src)
                            end
                            
                        elseif com.value == Commands_values.READ then -- read command
                            
                            if smb2_nt_status[i].value == 0 then
                                host_info[ip_dst_src].read.succ = increment_value(host_info[ip_dst_src].read.succ)
                            else
                                -- If nt_status is != 0 the operation has terminated with error
                                host_info[ip_dst_src].read.fail = increment_value(host_info[ip_dst_src].read.fail)
                            end
                        elseif com.value == Commands_values.WRITE then -- write command
                            
                            if smb2_nt_status[i].value == 0 then
                                host_info[ip_dst_src].write.succ = increment_value(host_info[ip_dst_src].write.succ)
                            else
                                -- If nt_status is != 0 the operation has terminated with error
                                host_info[ip_dst_src].write.fail = increment_value(host_info[ip_dst_src].write.fail)
                            end
                        
                        elseif com.value == Commands_values.SETINFO then -- setinfo command
                            
                            smb2_file_info_infolevel = { f_smb2_file_info_infolevel() }
                            
                            --the infolevel file field gives us the 
                            -- type of setInfo that has been requested. We are interested in the value 13 which corresponds to the command to delete the file on closure

                            if smb2_file_info_infolevel[info_lv_count].value == 13 then
                                
                                if smb2_nt_status[i].value == 0 then
                                    -- If nt_status is != 0 the operation has terminated with error
                                    host_info[ip_dst_src].delete.succ = increment_value(host_info[ip_dst_src].delete.succ)
                                else
                                    host_info[ip_dst_src].delete.fail = increment_value(host_info[ip_dst_src].delete.fail)
                                end
                            end
                            info_lv_count = increment_value(info_lv_count)
                        end 
                    end
                end
            end
        end
    end

    
    -- This function will be called once every few seconds to update our window
    function tap.draw(t)
        tw:clear()

        anomaly_checker()
        
        local function print_if_not_zero(count, succ, fail, str_op)
            if not(count == 0 and succ == 0 and fail == 0) then
                tw:append(string.format("%s\trequests: %6d \t| success responses: %6d \t| fail responses: %6d\n", str_op, count, succ, fail))
            end
        end

        if table.is_empty(host_info) then
            tw:append("No info, regarding SMB, obtained from this capture.")
        else
            
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

                -- Prints all data for all host
                tw:append(key .. "\n\n")
                print_if_not_zero(create.count, create.succ, create.fail, "CREATE")
                print_if_not_zero(open.count, open.succ, open.fail, "OPEN")
                print_if_not_zero(superseded.count, superseded.succ, superseded.fail, "SUPERSEDED")
                print_if_not_zero(overwrite.count, overwrite.succ, overwrite.fail, "OVERWRITE")
                print_if_not_zero(read.count, read.succ, read.fail, "READ")
                print_if_not_zero(write.count, write.succ, write.fail, "WRITE")
                print_if_not_zero(delete.count, delete.succ, delete.fail, "DELETE")
                print_if_not_zero(rename.count, rename.succ, rename.fail, "RENAME")
                tw:append("\n---\n");

                -- Prints a message with the risk detected
                if value.risk == Anomaly_code.RISK_CODE then
                    tw:append("Risk of cryptolocker detected\n")
                elseif value.risk == Anomaly_code.POTENTIAL_RISK_CODE then
                    tw:append("Potential risk of cryptolocker detected\n")
                else
                    tw:append("No risk of cryptolocker detected\n")
                end
            end
        end
    end

    -- This function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        
        tw:clear()
    end

    -- Ensure that all existing packets are processed
    retap_packets()

end

-- Menu GR -> DNS_ratio
register_menu("Project/Analyzer", gr_tap, MENU_TOOLS_UNSORTED)