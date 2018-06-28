--[[ FUNCTIONS --]] 
-- Stampa il valore di tutte le metriche di un protocollo social
function allMetrics (protoNdpiStats)
	local firstTime = true
	for key,value in pairs(protoNdpiStats) do
		if(type(value) == "table") then
			for key2,value2 in pairs(value) do
				if( not firstTime) then
				print(", ")
				end
				print("\""..(key:sub(1,1):upper()..key:sub(2)).." "..(key2:sub(1,1):upper()..key2:sub(2)).."\": ".. value2)
				firstTime = false
			end
		else -- if table
			if( not firstTime) then
				print(", ")
			end
			print("\""..(key:sub(1,1):upper()..key:sub(2)).."\": ".. value)
		end
		firstTime = false
	end -- for protoNdpiStats
	print("}")
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
print "[ "
for protoName,_ in pairs(socialProtos) do
	protoNdpiStats = stats[protoName]
	if(protoNdpiStats ~= nil) then
		-- Se esiste un flusso per questo tipo di social
		if( not firstTime) then
			-- Dal secondo oggetto in poi la virgola tra il precedente e il corrente
			print(",")
		end
		
		if( metric == nil) then
			print(" {\"Application Name\": \"".. protoName .."\", ")
			allMetrics(protoNdpiStats)
		else
			print(" {\"label\": \"".. protoName .."\", ")
			singleMetric(protoNdpiStats,metric)
		end
		firstTime = false
	end -- if protoNdpiStats
end -- for socialProtos
print " ]"


