-- Chisel description
description = "Shows the number of BRK called and the memory size allocated, grouping processes in order to allocated memory."
short_description = "Report memory allocations and process memory sizes by parsing BRK"
category = "Process"


-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"
grtable = {}

TOP_NUMBER = 10

-- Argument notification callback

-- Initialization callback
function on_init()
	-- Request the fields we need
	fkey = chisel.request_field("proc.pid")
	fname = chisel.request_field ("proc.name")
	fevt = chisel.request_field("evt.type")
    	fdir = chisel.request_field("evt.dir") 
	fsize = chisel.request_field("evt.arg.res")
	
	
	return true
end

-- Event parsing callback
function on_event()
	
	key = evt.field(fkey)
	sName = evt.field ( fname )
	evtS= evt.field(fevt)
	evtDir = evt.field(fdir)
	evtSize = evt.field(fsize)
	
	

	if evtS == "brk" and evtDir == "<" then
		entryval = grtable[key]
 		if entryval == nil then
			grtable[key] = {}
			grtable[key]["name"] = sName
			grtable[key]["sHeap"] = tonumber (evtSize, 16)
			grtable[key]["fHeap"] = 0
			grtable[key]["size"] = 0
		else 	
			grtable[key]["fHeap"] = tonumber(evtSize, 16)
			grtable[key]["size"] = ( (grtable[key]["fHeap"] - grtable[key]["sHeap"]) )
		end
	end
	

	return true
end

-- Interval callback, emits the ourput
function on_capture_end()
	sorted_grtable = pairs_top_by_val(grtable, TOP_NUMBER, function(t,a,b) return t[b]["size"] < t[a]["size"] end)
	

	terminal.clearscreen()
	terminal.goto(0 ,0)
		print ( "Process : \n[ Pid ] [ Name ] [ VmSize ] ")
	for k,v in sorted_grtable do
		print(k .."   |   "..v["name"].."\t\t".. v["size"])
	end
	
	return true
end
