description = "Traffic Done by Processes"
short_description = "Processes' Traffic"
category = "misc"

-- Chisel argument list
args = 
{
    {
        name = "interval", 
        description = "Set the update interval", 
        argtype = "int"
    },
}
ProcToCheck={}
--The last n second result
TempProcIn = {}
TempProcOut = {}
--The amount from the beginning
TotIn = {}
TotOut = {} 
--The last results collected
LastIn = {}
LastOut = {}

file = io.open("Log_" .. os.date("%d.%m.%Y_%H:%M"), "a")
function findLast(haystack, needle)
    local i=haystack:match(".*"..needle.."()")
    if i==nil then return 0 else return i-1 end
end
function on_init()
    -- Request the fileds that we need
    pr = chisel.request_field("proc.exe")
    pid = chisel.request_field("proc.pid")
    r_byte = chisel.request_field("evt.res")
    sys_call = chisel.request_field("evt.type")
    --Setting filters
	chisel.set_filter('evt.type="recv" or evt.type="recvmsg" or evt.type="recvfrom" or evt.type="send" or evt.type="sendto" and fd.type="ipv4"')
	return true
end
function on_set_arg(name, val)
	if tonumber(val) ~= nil then
		chisel.set_interval_s(val)
	else
		print("The parameter must be a number!")
		os.exit()
	end;

	return true
end
function on_interval(ts_s, ts_ns, delta)
	os.execute( "clear" )
	local toPrint="		  REPORT\n-------------------------------------------------\n           " .. os.date("%d.%m.%Y  %H:%M:%S") .."\n"
	print(toPrint)
	file:write(toPrint)
	--Starting Printing preparation
	for k, v in pairs(ProcToCheck) do
		toPrint=k .. "\nIn:"
		if TempProcIn[k] ~= nil then
			if TotIn[k] ~= nil then
				TotIn[k]=TotIn[k]+tonumber(TempProcIn[k])
			else
				TotIn[k]=TempProcIn[k]
			end
			
			toPrint=toPrint .. TotIn[k]
			toPrint=toPrint .. " LastIn:" .. TempProcIn[k]
			toPrint = toPrint .. " DiffLast:"
			if LastIn[k]  == nil then
				LastIn[k]=0
			end
			toPrint = toPrint .. (TempProcIn[k]-LastIn[k])
			LastIn[k]=TempProcIn[k]
		else  -- if there is no update for the process
			if TotIn[k] ~= nil then
				toPrint=toPrint .. TotIn[k]
			else
				toPrint=toPrint .. "0"
			end
			toPrint=toPrint .. " LastIn:0 DiffLast:"
			if LastIn[k] == nil then
				LastIn[k]=0
			end
			toPrint=toPrint .. (0-LastIn[k])
			LastIn[k]=0
		end
		--preparing out statistic line
		toPrint=toPrint .. "\nOut:"
		if TempProcOut[k] ~= nil then
			if TotOut[k] ~= nil then
				TotOut[k]=TotOut[k]+tonumber(TempProcOut[k])
			else
				TotOut[k]=TempProcOut[k]
			end
			
			toPrint=toPrint .. TotOut[k]
			toPrint=toPrint .. " LastOut:" .. TempProcOut[k]
			toPrint = toPrint .. " DiffLast:"
			if LastOut[k]  == nil then
				LastOut[k]=0
			end
			toPrint = toPrint .. (TempProcOut[k]-LastOut[k])
			LastOut[k]=TempProcOut[k]
		else  -- if there is no update for the process..
			if TotOut[k] ~= nil then
				toPrint=toPrint .. TotOut[k]
			else
				toPrint=toPrint .. "0"
			end
			toPrint=toPrint .. " LastOut:0 DiffLast:"
			if LastOut[k] == nil then
				LastOut[k]=0
			end
			toPrint=toPrint .. (0-LastOut[k])
			LastOut[k]=0
		end
		toPrint=toPrint .. "\n\n"
		print(toPrint)
		file:write(toPrint)
	end
	file:write("\n")
	TempProcIn={}
	TempProcOut={}
	return true
end
-- Event parsing callback
function on_event()
	ris=evt.field(r_byte)
	--Getting Proc name without absolute path..
	evtProc = evt.field(pr) .. "  PID:" .. evt.field(pid)
	if  ris ~= "EAGAIN" and ris ~= "-1" and ris ~= "0" and ris ~= nil then
		ris=tonumber(ris)
		if ris == nil then 
		   return true
		end
		ProcToCheck[evtProc] = 1
		if string.find("recv recvmsg recvfrom", evt.field(sys_call)) ~= nil then
			
			if TempProcIn[evtProc] ~= nil then
				TempProcIn[evtProc] = TempProcIn[evtProc] + ris
			else
				TempProcIn[evtProc] = ris
			end
		else
			if TempProcOut[evtProc] ~= nil then
				TempProcOut[evtProc] = TempProcOut[evtProc] + ris
			else
				TempProcOut[evtProc] = ris
			end
		end
	end
    return true
end
