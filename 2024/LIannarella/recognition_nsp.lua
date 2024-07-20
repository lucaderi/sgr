
local l7_proto = Proto("l7", "Layer 7 Protocol")
l7_proto.fields = {}

local l7_fds    = l7_proto.fields
l7_fds.proto    = ProtoField.new("Protocol Name", "l7.proto", ftypes.STRING)

local request_table = {}
local flows_table = {}
local processed_packets = {}
local old_id_packet = 0

local f_stun_type = Field.new("stun.type")
local f_stun_classic_type = Field.new("classicstun.type")
local f_stun_length = Field.new("stun.length")
local f_stun_username =  Field.new("stun.att.username")
local f_stun_tie_breaker = Field.new("stun.att.tie-breaker")
local f_stun_unknown_att = Field.new("stun.unknown_attribute")
local f_stun_realm = Field.new("stun.att.realm")
local f_stun_nonce = Field.new("stun.att.nonce")
local f_stun_software = Field.new("stun.att.software")
local f_stun_ip_xor = Field.new("stun.att.ipv4-xord")
local f_stun_ms_version = Field.new("stun.att.ms.version")
local f_stun_ms_version_ice = Field.new("stun.att.ms.version.ice")
local f_stun_response_to = Field.new("stun.response-to")
local f_udp_traffic = Field.new("udp")
local f_src_ip = Field.new("ip.src")
local f_dst_ip = Field.new("ip.dst")
local f_src_port = Field.new("udp.srcport")
local f_dst_port = Field.new("udp.dstport")


--##################################################

local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

--##################################################

local function develop_table(tab,key1,key2,protocol)
	if tab[key1] == nil then
		if tab[key2] ==  nil then 
			tab[key1] = protocol
		end
	end
	return tab
end

--##################################################

-- the dissector function callback
function l7_proto.dissector(tvb, pinfo, tree)
   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice
   
	if pinfo.visited then
		local id_packet = pinfo.number
    	local udp_traffic = f_udp_traffic()
		
		if udp_traffic then	 
            if old_id_packet > id_packet then
                processed_packets = flows_table
                flows_table = {}
                old_id_packet = id_packet
            end
			local src = getstring(f_src_ip())
			local dst = getstring(f_dst_ip())
			local src_port = getstring(f_src_port())
			local dst_port = getstring(f_dst_port())
			local stun_type = getstring(f_stun_type())
			local stun_length = getstring(f_stun_length())
			local classic_type = getstring(f_stun_classic_type())
			local stun_username = f_stun_username()
			local stun_tie_breaker = f_stun_tie_breaker()
			local stun_unknown_att = f_stun_unknown_att()
			local stun_realm = f_stun_realm()
			local stun_nonce = f_stun_nonce()
			local stun_software = f_stun_software()
			local stun_ip_xor = f_stun_ip_xor()
			local stun_ms_version = f_stun_ms_version()
			local stun_ms_version_ice = f_stun_ms_version_ice()
			local stun_request = f_stun_response_to()
			local protocol = ""

			local key = src..":"..src_port.." <--> "..dst..":"..dst_port
			local key2 = dst..":"..dst_port.." <--> "..src..":"..src_port


			--         Send Data       
			if stun_type == "0x0016"  then
                -- da sistemare, guarda meet_test1.pcap
				protocol = (flows_table[key] ~= nil) and flows_table[key] or (flows_table[key2] ~= nil) and flows_table[key2] or ""
			
				--  Data Indication 
			elseif stun_type == "0x0017" then
				protocol = (stun_software ~= nil) and "Telegram" or "Teams"
				flows_table = develop_table(flows_table,key,key2,protocol)

			--	Create Permission Request 
			elseif stun_type == "0x0008" then
				protocol = (getstring(stun_realm) == "telegram.org") and "Telegram" or "Teams"
				flows_table = develop_table(flows_table,key,key2,protocol)
			
			-- Refresh Request
			elseif stun_type == "0x0004" then
				protocol = (stun_ms_version ~= nil and stun_username ~= nil) and "Teams" or (getstring(stun_realm) == "telegram.org") and "Telegram" or "Teams"
				flows_table = develop_table(flows_table,key,key2,protocol)
			-- Create Permission Response
			elseif stun_type =="0x0108" then
				protocol = (stun_software ~= nil) and "Telegram" or "Teams"
				flows_table = develop_table(flows_table,key,key2,protocol)
			
			-- Refresh Success Response
			elseif stun_type == "0x0104" then
				protocol = (stun_software ~= nil) and "Telegram" or "Teams"
				flows_table = develop_table(flows_table,key,key2,protocol)
			-- unknown request whatsapp
			elseif stun_type == "0x0800" then
				protocol = "Whatsapp"
				flows_table = develop_table(flows_table,key,key2,protocol)

			-- binding request   
			elseif stun_type == "0x0001" then  
				local telegram_tie_breaker = "00:00:00:00:00:00:00:00"
				if (stun_username and stun_unknown_att) or stun_ms_version_ice ~= nil or stun_ms_version  ~= nil then
					protocol = "Teams"
				elseif stun_tie_breaker ~= nil and stun_username ~= nil then
					if getstring(stun_tie_breaker) == telegram_tie_breaker   and getstring(stun_username):len()== 9 then 
						protocol = "Telegram"
					elseif getstring(stun_tie_breaker) ~= telegram_tie_breaker and getstring(stun_username):len()== 9  then
						protocol = "Teams"
					elseif getstring(stun_username):len() == 73 then
						protocol = "Zoom"
					elseif getstring(stun_tie_breaker) ~= telegram_tie_breaker and getstring(stun_username):len()~= 9  then
						protocol = "Meet"
					end	
				elseif tonumber(stun_length) == 0 then
					protocol = (flows_table[key] ~= nil) and flows_table[key] or (flows_table[key2] ~= nil) and flows_table[key2] or ""

				elseif tonumber(stun_length) == 24 then
					protocol = "Whatsapp"
				end
				request_table[getstring(pinfo.number)]= protocol
				flows_table = develop_table(flows_table,key,key2,protocol)

			-- binding request
			elseif classic_type == "0x0001" then
				protocol = "Zoom"
				flows_table = develop_table(flows_table,key,key2,protocol)

			-- binding success response 
			elseif classic_type == "0x0101"then
				protocol = "Zoom"
				flows_table = develop_table(flows_table,key,key2,protocol)
				
			-- shared Secret Request
			elseif classic_type == "0x0002" then
				protocol = "Zoom"
				flows_table = develop_table(flows_table,key,key2,protocol)
				
			-- allocate request
			elseif stun_type == "0x0003" then
				if stun_ms_version then
					protocol = "Teams"
				elseif stun_unknown_att then 
					protocol = "Whatsapp"
				elseif stun_realm and stun_nonce and stun_username then 
					protocol = "Telegram"
				else
					protocol = "Telegram"
				end
				flows_table = develop_table(flows_table,key,key2,protocol)
			
			-- binding success response
			elseif stun_type == "0x0101" then

				if tonumber(stun_length) == 44 or tonumber(stun_length) == 12 then
					protocol = request_table[getstring(stun_request)]
				else
					if stun_ms_version_ice then 
						protocol = "Teams"
					elseif stun_software then 
						protocol = "Telegram"
					elseif (stun_software == nil) and stun_ip_xor then
						protocol = "Meet"
					elseif tonumber(stun_length) == 24 then
						protocol = "Whatsapp"
					end
				end
				if request_table[getstring(stun_request)] ~= "" and protocol ~= request_table[getstring(stun_request)] then
					protocol = request_table[getstring(stun_request)]
				
				end
				flows_table = develop_table(flows_table,key,key2,protocol)


			-- Allocate Success Response
			elseif stun_type == "0x0103" then
				protocol = (stun_ms_version ~= nil) and "Teams" or (stun_software ~= nil) and "Telegram" or "Whatsapp"
				flows_table = develop_table(flows_table,key,key2,protocol)


			-- Allocate Error Response
			elseif stun_type == "0x0113"  then
				protocol = (stun_ms_version ~= nil) and "Teams" or (stun_realm ~= nil) and "Telegram" or ""
				flows_table = develop_table(flows_table,key,key2,protocol)

			-- Create permission error response
			elseif stun_type == "0x0118"  then 
				protocol = "Telegram"
				flows_table = develop_table(flows_table,key,key2,protocol)
			end
			
			if(protocol ~= "") then
				local subtree = tree:add(l7_proto, tvb(), "Application Protocol")
				subtree:add(l7_fds.proto, protocol)
                old_id_packet = id_packet
			elseif(protocol == "") then
				local subtree = tree:add(l7_proto, tvb(), "Application Protocol")
				if flows_table[key] ~= nil then 
					subtree:add(l7_fds.proto,flows_table[key])
				elseif flows_table[key2] ~= nil then
					subtree:add(l7_fds.proto,flows_table[key2])
                elseif old_id_packet > id_packet then
                    protocol = processed_packets[key] ~= nil and processed_packets[key] or processed_packets[key2] ~= nil and processed_packets[key2] or ""
                    subtree:add(l7_fds.proto,protocol)
                end
                old_id_packet = id_packet
            end
		end
   	end
end

register_postdissector(l7_proto)


function l7_proto.init()
	request_table = {}
	flows_table = {}
end