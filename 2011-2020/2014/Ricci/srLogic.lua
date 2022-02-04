logic = {
	--dimensione delle liste lru
	limit = 6,

	--conterrà i dati relativi ai file
	fileTab = {},
	--mantiene traccia dei limit file usati più di recente
	fileLruTab = {},

	--conterrà i dati relativi alle comunicazioni di rete
	socketTab = {},
	
	--mantiene traccia dei limit scoket usati più di recente
	socketLruTab = {},

	--[[
		Archivia i dati di un evento relativo ad un file:
		se l'evento è relativo ad un nuovo file crea una nuova
		entry in fileTab, inoltre aggiorna il contenuto di fileLruTab.
		Una entry ha formato:
			k: stringa, nome del file(fullpath)
			fileType: stringa, tipo del file
			openCounter: intero positivo, conta le sysCall "open"
			readCounter: intero positivo, conta le operazioni di lettura
			writeCounter: intero positivo, conta le operazioni di scrittura
		Parametri:
			name -> nome(fullpath) del file
			fType -> tipo del file, uno tra {'file', 'pipe'}
			sysCall -> nome della sysCall o nil
			isRead -> booleano, true se l'evento è relativo ad una operazione di lettura
			isWrite -> booleano, true se l'evento è relativo ad una operazione di scrittura
		Ritorna:
			nil se l'evento non è stato archiviato
			altrimenti una stringa rappresentante l'evento nel formato:
				{nome_file, tipo_file, open/read/write}
	--]]
	manageFileEvent = function(name, fType, sysCall, isRead, isWrite)
		local key = logic.nilString(name)
		
		local record = logic.fileTab[key]
	
		if record==nil then
			record = {
				k = key,
				fileType = logic.nilString(fType),
				openCounter = 0,
				readCounter = 0,
				writeCounter = 0,
			}
		end
	
		if sysCall=="open" then
			record.openCounter = record.openCounter+1
		elseif isRead then
			record.readCounter = record.readCounter+1
		elseif isWrite then
			record.writeCounter = record.writeCounter+1
		end
	
		logic.fileTab[key] = record
	
		logic.refreshLruList(logic.fileLruTab, logic.fileTab[key], logic.limit)
		
		return string.format( "file:%s type:%s mode:%s%s%s",
						key,
						record.fileType,
						sysCall=="open" and "-o" or "",
						isRead and "-r" or "",
						isWrite and "-w" or "")
	end,

	--[[
		Archivia i dati di un evento relativo ad una comunicazione remota:
		se l'evento è relativo ad una nuova comunicazione crea una nuova
		entry in socketTab, inoltre aggiorna il contenuto di socketLruTab.
		Una entry ha formato:
			k: stringa, ip:porta del socket del server
			csocket: stringa, ip:porta del client
			protocol: stringa, protocollo utilizzato a livello trasporto
			role: "client" o "server"
			readCounter: intero positivo, conta le operazioni di lettura
			writeCounter: intero positivo, conta le operazioni di scrittura
		Parametri:
			sIp -> ip del server
			sPort -> porta del server
			cIp -> ip del client
			cPort -> porta del client
			proto -> protocollo di livello 4
			isServer -> booleano, true se localhost è server nella comunicazione
			isRead -> booleano, true se l'evento è relativo ad una operazione di lettura
			isWrite -> booleano, true se l'evento è relativo ad una operazione di scrittura
		Ritorna:
			nil se l'evento non è stato archiviato
			altrimenti una stringa rappresentante l'evento nel formato:
				{porta, socket_destinazione, protocollo, isServer, read/write}
	--]]
	manageSocketEvent = function(sIp, sPort, cIp, cPort, proto, isServer, isRead, isWrite)

		if sIp==nil and cIp==nil then
			return nil
		end

		local key = logic.ipCheck(sIp)..":"..logic.portCheck(sPort)
		local record = logic.socketTab[key]
		if record==nil then
			record = {
				k = key,
				cSocket = logic.ipCheck(cIp)..":"..logic.portCheck(cPort),
				protocol = logic.nilString(proto),
				role = (isServer==true and "server" or "client"),
				readCounter = 0,
				writeCounter = 0
			}
		
		end
		
		if isRead then
			record.readCounter = record.readCounter+1;
		elseif isWrite then
			record.writeCounter = record.writeCounter+1;
		end
	
		logic.socketTab[key] = record
	
		logic.refreshLruList(logic.socketLruTab, logic.socketTab[key], logic.limit)
		
		return string.format( "port:%s to:%s proto:%s isServ:%s %s%s",
					isServer and sPort or logic.portCheck(cPort),
					isServer and record.cSocket or key,
					proto and proto or "n/a",
					tostring(isServer),
					isRead and "r" or "",
					isWrite and "w" or "")
	end,
	
	
	--[[
		Aggiunge un nuovo elemento ad una lista lru, la quale ha lunghezza finita.
		Se l'elemento da aggiungere era già presente, la vecchia istanza viene rimossa.
		Parametri:
		l -> la lista, in realtà una tabella
		e -> elemento da aggiungere
		lim -> dimensione della lista
	--]]
	refreshLruList = function(l, e, lim)
		local old = e
		for i=1, lim do
			if l[i]==nil then
				l[i] = old
				return
			end
			if l[i].k == e.k then
				l[i] = old
				return
			end
		
			l[i],old = old,l[i]
		end	
	end,
	
	--[[
		Ritorna la rappresentazione testuale del parametro,
		se quest'ultimo è nil ritorna la stringa "nil".
	--]]
	nilString = function(arg)
		if arg~=nil then
			return tostring(arg)
		end
	
		return "nil"
	end,


	--[[
		se p è nil ritorna -1 altrimenti ritorna p
	--]]
	portCheck = function(p)
		if p==nil then 
			return -1
		end
		return p
	end,


	--[[
		se ip è nil ritorna "?.?.?.?" altrimenti ritorna ip
	]]--
	ipCheck = function(ip)
		if ip==nil then 
			return "?.?.?.?"
		end
		return ip
	end
	
}
