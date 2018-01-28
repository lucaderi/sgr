description = "Questo chisel considera tutti gli eventi relativi a pipes(con e senza nome), files, e comunicazioni di rete di un processo o di eseguibile al fine ci creare un report di sicurezza."..
"Durante il parsing degli eventi stampa periodicamente le ultime risorse utilizzate, mentre al termine stampa il riepilogo di tutti gli eventi catturati."
short_description = "visualizza files, pipe, e comunicazioni di un processo"
category = "misc"

--lista degli argomenti del chisel
args = 
{
    {
        name = "p", 
        description = "un PID o il nome di un eseguibile", 
        argtype = "string"
    },
    {
        name = "log", 
        description = "se vale s, si, y, yes ogni evento rilevante sarà salvato nel file scRepEventLog_[data_ora]", 
        argtype = "string"
    }
}

--carico le "librerie"
outLib = assert(loadfile("srOut.lua"), "can't find srOut.lua, or it contains errors")
outLib()
logicLib = assert(loadfile("srLogic.lua"), "can't find srLogic.lua, or it contains errors")
logicLib()

--terrà traccia del tempo per temporizzare le stampe delle liste lru
oldTime = nil

--[[
	callback di notifica degli argomenti:
	effettua controlli sulla correttezza dell'unico
	argomento richiesto
--]]
function on_set_arg(name, val)
	if name=="p" then
		if type(tonumber(val)) == "number" then
			pid = val
			print("searching for pid: " .. pid)
		elseif type(val) == "string" then
			exe = val
			print("searching for exe: " .. exe)
		else
			print("wrong argument type, exiting...")
			return false
		end
	
	elseif name=="log" then
		if val=="s" or val=="si" or val=="y" or val=="yes" then
			logMode = "yes"
		end
		
	else
		print("wrong arguments, exiting...")
		return false
	end
	
    return true
end

--[[
	callback di inizializzazione:
	comunica a sysdig i campi necessari al chisel,
	imposta il filtro per gli eventi
--]]
function on_init()
	--creo file di log eventi, se richiesto
	if logMode then
		logFile = assert(io.open("scRepLog"..os.date("%X_%b.%d.%Y", os.time())..".txt", "w"))
		logFile:write((pid and "PID:"..tostring(pid) or "exe:"..exe) .. "\n")
	end
	
	-- campi richiesti
    evtType = chisel.request_field("evt.type")
    evtIsRead = chisel.request_field("evt.is_io_read")
    evtIsWrite = chisel.request_field("evt.is_io_write")
    evtFdType = chisel.request_field("fd.type")
    evtFdName = chisel.request_field("fd.name")
    evtFdSPort = chisel.request_field("fd.sport")
    evtFdCPort = chisel.request_field("fd.cport")
	evtFdSIP = chisel.request_field("fd.sip")
	evtFdCIP = chisel.request_field("fd.cip")
    evtFdProto = chisel.request_field("fd.l4proto")
    evtFdServer = chisel.request_field("fd.is_server")
    
    --mi preparo ad impostare il filtro
   	local filter = nil
    
    if pid~=nil then
    	filter = "proc.pid="..pid
    	
    else
    	filter = "proc.name="..exe
    end
    
    filter = filter.." and (fd.type=ipv4 or fd.type=ipv6 or fd.type=file or fd.type=pipe)"
    filter = filter.." and (evt.is_io_read=true or evt.is_io_write=true or evt.type=open or evt.type=socket"
    filter = filter..	" or evt.type=accept or evt.type=listen or evt.type=bind or evt.type=connect)"
    filter = filter.." and evt.dir = <"
    
    -- imposto il filtro
    chisel.set_filter(filter)

    return true
end

--[[
	callback per gli eventi:
	discrimina tra eventi relativi a files ed
	eventi relativi a comunicazioni remote,
	in entrambi i casi salva i dati dell'evento
	nell'apposita tabella,
	ogni secondo stampa il contenuto delle
	liste lru,
	inoltre, se richiesto, salva ogni evento
	rilevante nel file di log.
--]]
function on_event()
	local newTime = os.time()
    local isRead = evt.field(evtIsRead)
    local isWrite = evt.field(evtIsWrite)
    local fdType = evt.field(evtFdType)
    
    -- caso comunicazione remota
    if fdType=="ipv4" or fdType=="ipv6" then
    	local fdSIP = evt.field(evtFdSIP)
    	local fdCIP = evt.field(evtFdCIP)
    	local fdCPort = evt.field(evtFdCPort)
    	local fdSPort = evt.field(evtFdSPort)
    	local fdProto = evt.field(evtFdProto)
    	local fdIsServ = evt.field(evtFdServer)
    	local toLog = logic.manageSocketEvent(fdSIP, fdSPort, fdCIP, fdCPort, fdProto, fdIsServ, isRead, isWrite)
    	if logMode and toLog then
    		logFile:write(os.date("%X", newTime).." "..toLog.."\n")
    	end
    	
    --caso file
    else
    	local fdName = evt.field(evtFdName)
    	local sysCall = evt.field(evtType)
    	local toLog = logic.manageFileEvent(fdName, fdType, sysCall, isRead, isWrite)
    	if logMode and toLog then
    		logFile:write(os.date("%X", newTime).." "..toLog.."\n")
    	end
    	
    end
    
    
    --se è passato più di un secondo dall'ultima stampa,
    --stampa il contenuto delle liste lru
	if oldTime==nil or newTime-oldTime>=1 then
		oldTime = newTime
		out.doShortOutput(logic.limit)
	end
    
    return true
end

--[[
	callback di fine cattura eventi:
	stampa il contenuto delle tabelle dal
	record più utilizzato a quello meno
	utilizzato.
--]]
function on_capture_end()
	if logMode then
		logFile:close()
	end
	out.doLongOutput()
	return true
end
