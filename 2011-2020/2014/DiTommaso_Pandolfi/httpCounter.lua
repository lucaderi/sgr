-- Chisel description
description = "Shows the event timestamp, the name's and the pid's  process, the event direction, the name of the event and the event arguments every time that an http's request arrives and the number requests."
short_description = "List web requests by parsing HTTP GETs"
category = "Net"

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"
-- Initialization callback
function on_init()

	-- Request the fields we need
	fkey = chisel.request_field("proc.name")
	fevt = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir") 
	farg = chisel.request_field("evt.args")
	ftime = chisel.request_field("evt.time")
	fpid = chisel.request_field("thread.tid")
	fdata = chisel.request_field("evt.arg.data")
	
	-- Set the filter
	chisel.set_filter("fd.port=80 and (fd.type=ipv4 or fd.type=unix or fd.type=ipv6)")
	

	return true
end

-- Count the number
request = 0

-- Event parsing callback
function on_event()
	key = evt.field(fkey)
	evtS= evt.field(fevt)
	evtDir = evt.field(fdir)
	evtArg = evt.field(farg)
	evtTime = evt.field(ftime)
 	thPid = evt.field(fpid)
	str = evt.field(fdata)

	if (str~=nil and string.byte(str,1) == 71 and string.byte(str,2) == 69 and string.byte(str,3) == 84)  then
	  strTemp = string.match(str, "Host.*")
	  if (strTemp ~= nil) then
	    delim = string.find(strTemp, "..C")
	    if delim ~= nil then
	      if ( ( string.sub(strTemp, delim-2, delim-2) )== "." ) then
		  print(evtTime .." "..key .. "(".. thPid .. ") " ..evtDir .. " " .. evtS .. " " .. " \t\t @ " .. string.sub(strTemp, 0, delim-2) )
	      else 
		  print(evtTime .." "..key .. "(".. thPid .. ") " ..evtDir .. " " .. evtS .. " " .. " \t\t @ " .. string.sub(strTemp, 0, delim-1) )
	      end
	    end
	  else 
	    print(evtTime .." "..key .. "(".. thPid .. ") " ..evtDir .. " " .. evtS .. " " .. evtArg)
	  end
	  request = request + 1
	end
	return true
end

-- Interval callback, emits the output
function on_capture_end()

  print("\nThe number of request is: " ..request)

  return true

end
