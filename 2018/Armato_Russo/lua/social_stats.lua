--[[ FUNCTIONS --]] 
-- Stampa il valore di tutte le metriche di un protocollo social

function allMetrics (protoNdpiStats)
    local duration = protoNdpiStats["duration"]
    local pcktsSent =protoNdpiStats["packets"]["sent"]
    local pcktsRcvd =protoNdpiStats["packets"]["rcvd"]
    local bytesSent = protoNdpiStats["bytes"]["sent"]
    local bytesRcvd = protoNdpiStats["bytes"]["rcvd"]
    print("<td align=right>"..secondsToTime(duration).."</td>")
    print("<td align=right>"..formatPackets(pcktsRcvd).."</td>")
    print("<td align=right>"..formatPackets(pcktsSent).."</td>")
    print("<td>")
    breakdownBar(pcktsRcvd, "Rcvd", pcktsSent, "Sent", 0, 100)
    print("</td>")
    print("<td align=right>"..formatPackets(pcktsRcvd + pcktsSent ).."</td>")
    
    print("<td align=right>"..bytesToSize(bytesRcvd).."</td>")
    print("<td align=right>"..bytesToSize(bytesSent).."</td>")
    print("<td>")
    breakdownBar(bytesRcvd, "Rcvd", bytesSent, "Sent", 0, 100)
    print("</td>")
    print("<td align=right>"..bytesToSize(bytesRcvd + bytesSent).."</td>")
end

-- Stampa il valore della metrica di un protocollo social
function singleMetric (protoNdpiStats, metric)
	protoValue = protoNdpiStats[metric]
	if( metric == "bytes" or metric == "packets") then
		protoValue = protoValue["sent"] + protoValue["rcvd"]
	end	
	print("\"value\": ".. protoValue .." }")
end

--[[ END FUNCTIONS --]] 

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path
require "lua_utils"
require "format_utils"
require "graph_utils"


json = require("dkjson")
sendHTTPContentTypeHeader('text/html')

local host_ip = _GET["host"]
--[[
	Se metric = nil allora diamo tutti i valori delle metriche disponibili
	altrimenti diamo solo la metrica richiesta tra le tre disponibili
--]]
local metric = _GET["p_metric"]
hostInfo = interface.getHostInfo(host_ip)
if(hostInfo == nil or (metric ~= nil and metric ~= "duration" and metric ~= "bytes" and metric ~= "packets")) then 
	print "[ ]"
	return 
end

jsonString = hostInfo.json
local info, pos, err = json.decode(jsonString, 1, nil)
if( err or (info.localHost) == false) then
	-- Se c'è stato un errore nella decodifica oppure l'ip non è locale
	print("[ ]")
	return
end

stats = info.ndpiStats
socialFlowExists = stats["categories"]["SocialNetwork"]
if (socialFlowExists == nil) then
	print("[ ]")
	return 
end

-- Per capire dove mettere la virgola tra due oggetti json
firstTime = true
catId = interface.getnDPICategoryId("SocialNetwork")
-- Table con tutti i protocolli con categoria SocialNetwork
socialProtos = interface.getnDPIProtocols(catId)
if (metric ~= nil) then
    print "[ "
end
for protoName,_ in pairs(socialProtos) do
	protoNdpiStats = stats[protoName]
	if(protoNdpiStats ~= nil) then
		-- Se esiste un flusso per questo tipo di social
		if( (not firstTime) and metric ~=nil) then
			-- Dal secondo oggetto in poi la virgola tra il precedente e il corrente
			print(",")
		end
		if( metric == nil) then
            print("<tr>")
            print("<td>"..protoName)
			allMetrics(protoNdpiStats)
            print("</td>")
            print("</tr>")        
		else
			print(" {\"label\": \"".. protoName .."\", ")
			singleMetric(protoNdpiStats,metric)
		end
		firstTime = false
	end -- if protoNdpiStats
end -- for socialProtos
if (metric ~= nil) then
    print " ]"
end
