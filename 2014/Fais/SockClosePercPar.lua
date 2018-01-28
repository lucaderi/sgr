-- Chisel description
description = "Usage of socket done by processes and close of respective file descriptors"
short_description = "Socket and close monitoring"
category = "misc"

-- Chisel argument list
args = 
{
	{
        name = "process", 
        description = "Set process to monitor", 
        argtype = "string"
    },
}

-- Chisel data structures (number of socket and close and file descriptors in use)
-- Number of socket
ProcSocket = {}
ProcLastSocket = {}
-- Number of socket tcp, udp, other
SockTCP = {}
SockLastTCP = {}
SockUDP = {}
SockLastUDP = {}
OtherSock = {}
OtherSockLast = {}
-- Number of close
ProcClose = {}
ProcLastClose = {}
-- Number of close tcp, udp, other
CloseTCP = {}
CloseLastTCP = {}
CloseUDP = {}
CloseLastUDP = {}
OtherClose = {}
OtherCloseLast = {}
-- File descriptors
FileDesc = {}
-- Process' details
ProcPID = {}
ProcDuration = {}
OldProcDuration = {}
StartTimeProc = {}

-- Function that looks for process' name in his absolute path
function findLast(pathname, pattern)
    local i = pathname:match(".*"..pattern.."()")
    if i==nil then
    	return 0
    else
    	return i-1
    end
end

-- Function that deletes stopped or interrupted processes
function deleteStoppedProcess(proc)
	ProcSocket[proc] = nil
	ProcLastSocket[proc] = nil
	SockTCP[proc] = nil
	SockLastTCP[proc] = nil
	SockUDP[proc] = nil
	SockLastUDP[proc] = nil
	OtherSock[proc] = nil
	OtherSockLast[proc] = nil
	ProcClose[proc] = nil
	ProcLastClose[proc] = nil
	CloseTCP[proc] = nil
	CloseLastTCP[proc] = nil
	CloseUDP[proc] = nil
	CloseLastUDP[proc] = nil
	OtherClose[proc] = nil
	OtherCloseLast[proc] = nil
	FileDesc[proc] = nil
	ProcPID[proc] = nil
	ProcDuration[proc] = nil
	OldProcDuration[proc] = nil
	StartTimeProc[proc] = nil
end

-- Function that calculates processes lifetime
function calcExecTime(pname, extime)
	-- Process' execution time in seconds
    local hour, min, sec = extime:match("(%d+):(%d+):(%d+)")
    extimesec = (hour*3600) + (min*60) + sec

	-- Process just started (saving initial execution time)
	if ProcPID[pname]==nil then
		ProcDuration[pname] = 0
		StartTimeProc[pname] = extimesec
	else
	-- Process in execution
		ProcDuration[pname] = extimesec - StartTimeProc[pname]
	end
end

-- Fields needed
function on_init()
    proc = chisel.request_field("proc.exe")
    procpid = chisel.request_field("proc.pid")
    procduration = chisel.request_field("evt.time.s")
    fd = chisel.request_field("fd.num")
    syscall = chisel.request_field("evt.type")
    dir = chisel.request_field("evt.dir")
    arguments = chisel.request_field("evt.args")
    chisel.set_interval_s(7) 
    return true
end

-- Arguments setting and system call's filter setting
function on_set_arg(name, val)
	if val=="all" then
    	chisel.set_filter('evt.type=socket or evt.type=close')
	else
    	chisel.set_filter('proc.name="'..val..'" and evt.type=socket or evt.type=close')
	end
	return true
end

-- Print of statistics about collected data
function on_interval()
	os.execute("clear")
	for k, v in pairs(ProcSocket) do
		print("Process name: "..k)
		if ProcDuration[k]~=nil then
			if OldProcDuration[k]==nil or OldProcDuration[k]<ProcDuration[k] then
				pdur = ProcDuration[k]
			else
				pdur = ProcDuration[k].." [process stopped]"
			end
		else
			pdur = "-"
		end
		print("Process PID:  "..ProcPID[k].."     ".."ProcessDuration:  "..pdur)
		if ProcLastSocket[k]~=nil then
			pls = ProcLastSocket[k]
		else
			pls = 0
		end
		if ProcClose[k]~=nil then
			pc = ProcClose[k]
		else
			pc = 0
		end
		if ProcLastClose[k]~=nil then
			plc = ProcLastClose[k]
		else
			plc = 0
		end

		stillop = v - pc
		print("SocketTOT     SocketLAST      CloseTOT      CloseLAST      StillOPEN")
		print("  "..v.."              "..pls.."              "..pc.."             "..plc.."             "..stillop)

		if SockTCP[k]~=nil then
			tcp = SockTCP[k]
		else
			tcp = 0
		end
		if SockLastTCP[k]~=nil then
			lasttcp = SockLastTCP[k]
		else
			lasttcp = 0
		end
		if SockUDP[k]~=nil then
			udp = SockUDP[k]
		else
			udp = 0
		end
		if SockLastUDP[k]~=nil then
			lastudp = SockLastUDP[k]
		else
			lastudp = 0
		end
		if OtherSock[k]~=nil then
			other = OtherSock[k]
		else
			other = 0
		end
		if OtherSockLast[k]~=nil then
			lastother = OtherSockLast[k]
		else
			lastother = 0
		end

		if CloseTCP[k]~=nil then
			ctcp = CloseTCP[k]
		else
			ctcp = 0
		end
		if CloseLastTCP[k]~=nil then
			clasttcp = CloseLastTCP[k]
		else
			clasttcp = 0
		end
		if CloseUDP[k]~=nil then
			cudp = CloseUDP[k]
		else
			cudp = 0
		end
		if CloseLastUDP[k]~=nil then
			clastudp = CloseLastUDP[k]
		else
			clastudp = 0
		end
		if OtherClose[k]~=nil then
			cother = OtherClose[k]
		else
			cother = 0
		end
		if OtherCloseLast[k]~=nil then
			clastother = OtherCloseLast[k]
		else
			clastother = 0
		end

		stillopTCP = tcp - ctcp
		stillopUDP = udp - cudp
		stillopOTHER = other - cother
		print("[TCP] "..tcp.."        [TCP] "..lasttcp.."        [TCP] "..ctcp.."        [TCP] "..clasttcp.."        [TCP] "..stillopTCP)
		print("[UDP] "..udp.."        [UDP] "..lastudp.."        [UDP] "..cudp.."        [UDP] "..clastudp.."        [UDP] "..stillopUDP)
		print("[OTHER] "..other.."      [OTHER] "..lastother.."      [OTHER] "..cother.."      [OTHER] "..clastother.."      [OTHER] "..stillopOTHER)

		print("  ")

		OldProcDuration[k] = ProcDuration[k]
		if string.find(pdur, " [process stopped]") then
			deleteStoppedProcess(k)
		end
	end
	FileDesc = {}
	ProcLastSocket = {}
	ProcLastClose = {}
	SockLastTCP = {}
	SockLastUDP = {}
	OtherSockLast = {}
	CloseLastTCP = {}
	CloseLastUDP = {}
	OtherCloseLast = {}
	return true
end

-- Event parsing callback
function on_event()
	curfd = evt.field(fd)
	curproc = evt.field(proc)
	nameproc = string.sub(curproc, findLast(curproc,"/")+1, string.len(curproc))
	time = evt.field(procduration)
	calcExecTime(nameproc, time)
	ProcPID[nameproc] = evt.field(procpid)
	scdir = evt.field(dir)
	sock = evt.field(arguments)

	-- Socket
	if evt.field(syscall)=="socket" then
	
		if scdir==">" then
			if string.find(sock, "AF_INET") then
				if string.find(sock, "type=1") then
					type = 1
				elseif string.find(sock, "type=2") then
					type = 2
				else
					type = 0
				end
			end
		else
			FileDesc[curfd] = type

			-- Counting all ip socket
			if ProcSocket[nameproc]==nil then
				ProcSocket[nameproc] = 1
			else
				ProcSocket[nameproc] = ProcSocket[nameproc] + 1
			end
			if ProcLastSocket[nameproc]==nil then
				ProcLastSocket[nameproc] = 1
			else
				ProcLastSocket[nameproc] = ProcLastSocket[nameproc] + 1
			end

			-- Counting tcp socket, udp socket and other socket
			if type==1 then
				if SockTCP[nameproc]==nil then
					SockTCP[nameproc] = 1
				else
					SockTCP[nameproc] = SockTCP[nameproc] + 1
				end
				if SockLastTCP[nameproc]==nil then
					SockLastTCP[nameproc] = 1
				else
					SockLastTCP[nameproc] = SockLastTCP[nameproc] + 1
				end
			else
				if type==2 then
					if SockUDP[nameproc]==nil then
						SockUDP[nameproc] = 1
					else
						SockUDP[nameproc] = SockUDP[nameproc] + 1
					end
					if SockLastUDP[nameproc]==nil then
						SockLastUDP[nameproc] = 1
					else
						SockLastUDP[nameproc] = SockLastUDP[nameproc] + 1
					end
				else
					if OtherSock[nameproc]==nil then
							OtherSock[nameproc] = 1
					else
						OtherSock[nameproc] = OtherSock[nameproc] + 1
					end
					if OtherSockLast[nameproc]==nil then
						OtherSockLast[nameproc] = 1
					else
						OtherSockLast[nameproc] = OtherSockLast[nameproc] + 1
					end				
				end
			end
		end
	else

	-- Close
		if FileDesc[curfd]~=nil then
	
			-- Counting all close
			if ProcClose[nameproc]==nil then
				ProcClose[nameproc] = 1
			else
				ProcClose[nameproc] = ProcClose[nameproc] + 1
			end
			if ProcLastClose[nameproc]==nil then
				ProcLastClose[nameproc] = 1
			else
				ProcLastClose[nameproc] = ProcLastClose[nameproc] + 1
			end

			-- Counting fd close of tcp socket, udp socket and other socket
			if FileDesc[curfd]==1 then
				if CloseTCP[nameproc]==nil then
					CloseTCP[nameproc] = 1
				else
					CloseTCP[nameproc] = CloseTCP[nameproc] + 1
				end
				if CloseLastTCP[nameproc]==nil then
					CloseLastTCP[nameproc] = 1
				else
					CloseLastTCP[nameproc] = CloseLastTCP[nameproc] + 1
				end
			else
				if FileDesc[curfd]==2 then
					if CloseUDP[nameproc]==nil then
						CloseUDP[nameproc] = 1
					else
						CloseUDP[nameproc] = CloseUDP[nameproc] + 1
					end
					if CloseLastUDP[nameproc]==nil then
						CloseLastUDP[nameproc] = 1
					else
						CloseLastUDP[nameproc] = CloseLastUDP[nameproc] + 1
					end
				else
					if OtherClose[nameproc]==nil then
						OtherClose[nameproc] = 1
					else
						OtherClose[nameproc] = OtherClose[nameproc] + 1
					end
					if OtherCloseLast[nameproc]==nil then
						OtherCloseLast[nameproc] = 1
					else
						OtherCloseLast[nameproc] = OtherCloseLast[nameproc] + 1
					end
				end
			end

			FileDesc[curfd] = nil
		end
	end
   return true
end

-- Management of chisel's interruption
function on_capture_end()
	print()
	print("Bye bye! Thank you for using this chisel.")
	return true
end