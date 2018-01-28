-- Chisel description
short_description = "Show the number of fork ( intercepting clone and execve ),  group by process name, on input interval "
category = "Process"

-- Chisel argument list
args = 
{
	{
		name = "interval", 
		description = "interval to refresh the rate", 
		argtype = "int"
	},
}

-- Default number of items to show 
TOP_NUMBER = 10

require "common"
terminal = require "ansiterminal"

-- Table where counting statics
grtable = {}

-- Initialization callback
function on_init()

	-- Request the fields we need
	fkey = chisel.request_field("proc.name")
	fevt = chisel.request_field("evt.type")
    	fdir = chisel.request_field("evt.dir") 

	chisel.set_interval_s ( 1 )

	return true
end

-- Event parsing callback
function on_event()
	
	key = evt.field(fkey)
	evtS= evt.field(fevt)
	evtDir = evt.field(fdir)

	-- grtable [ key ] ["c"] : count clone / grtable [ key ] ["e"] : count execve / grtable [ key ] ["t"] : sum clone and execve
	if evtS == "clone" and evtDir == ">"  then
		entryval = grtable[key]
 		if entryval == nil then
			grtable[key] = {}
			grtable[key]["c"] = 1
			grtable[key]["e"] = 0
			grtable[key]["t"] = grtable[key]["c"] + grtable[key]["e"]
		else
			grtable[key]["c"] = grtable[key]["c"] + 1
			grtable[key]["t"] = grtable[key]["c"] + grtable[key]["e"]
			
		end
	end
	if evtS == "execve" and evtDir == ">" then
		entryval = grtable[key]
 		if entryval == nil then
			grtable[key] = {}
			grtable[key]["e"] = 1
			grtable[key]["c"] = 0
			grtable[key]["t"] = grtable[key]["c"] + grtable[key]["e"]
		else
			grtable[key]["e"] = grtable[key]["e"] + 1
			grtable[key]["t"] = grtable[key]["c"] + grtable[key]["e"]
		end
	end

	return true
end


-- Interval callback, emits the ourput
function on_interval(delta)
	sorted_grtable = pairs_top_by_val(grtable, TOP_NUMBER, function(t,a,b) return t[b]["t"] < t[a]["t"] end)
	
	-- etime = evt.field(ftime)
		terminal.clearscreen()
		terminal.goto(0 ,0)
	
	for k,v in sorted_grtable do
		print ( " -------------------------------------------------------" )
		print ( "Process : " ..k )
		print ( "   | -- > Fork : "..v["c"] .." \tExecve : "..v["e"] .. " \tTot : " ..v["t"])
	end

	print ( "CTRL-C to quit ")
	return true
end

