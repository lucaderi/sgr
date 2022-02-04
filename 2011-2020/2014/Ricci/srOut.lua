local function mPrint(file, msg)
	file:write(msg.."\n")
	print(msg)
end

out = {

	--[[
		Ritorna la rappresentazione testuale di un record
		contenuto nella tabella fileTab. vedi srMain.lua.
		Parametri:
		record -> il record da convertire in stringa
	--]]
	fileRecordToString = function(record)
		return string.format("%-s\t%d\t%d\t%d\t%-s",
						record.fileType,
						record.openCounter,
						record.readCounter,
						record.writeCounter,
						record.k)
	end,


	--[[
		Ritorna la rappresentazione testuale di un record
		contenuto nella tabella socketTab. vedi srMain.lua.
		Parametri:
		record -> il record da convertire in stringa
	--]]
	socketRecordToString = function(record)
		local ret
		local format = "%-21s %-21s %-4s %-s (%d,%d)"
		if record.role=="client" then
			ret =  string.format(format,
						record.cSocket,
						record.k,
						record.protocol,
						record.role,
						record.readCounter,
						record.writeCounter)
		elseif record.role=="server" then
			ret =  string.format(format,
						record.k,
						record.cSocket,
						record.protocol,
						record.role,
						record.readCounter,
						record.writeCounter)
		end
	
		return ret
	end,


	--[[
		Ritorna, ed estrae, da una tabella il valore massimo
		indicato da una funzione comparatrice.
		Parametri:
		tab -> una tabella
		comp -> funzione comparatrice a due argomenti,
				deve ritornare true se il primo argomento
				è maggiore del secondo.
	--]]
	extractMax = function(tab, comp)
		local maxKey=nil
	
		for key in pairs(tab) do
			if maxKey==nil or comp(tab[key], tab[maxKey]) then
				maxKey = key
			end
		end
	
		if maxKey==nil then
			return nil
		end
	
		local ret=tab[maxKey]
		tab[maxKey]=nil
		return ret
	end,


	--[[
		Funzione comparatrice richiesta da extractMax.
		Ritorna true se a.readCounter+a.writeCounter > b.readCounter+b.writeCounter.
	--]]
	comparator = function(a, b)
		return a.readCounter+a.writeCounter > b.readCounter+b.writeCounter
	end,


	--[[
		Stampa sul terminale i dati relativi ai files e sockets
		usati più di recente
		Parametri:
			lim numero di record da stampare per files e sockets
	--]]
	doShortOutput = function(lim)
		--pulisco il terminale
		io.write("\27[2J")
	
		--stampo la tabella dei files acceduti recentemente
		print("type\topen\tread\twrite\tname")
		for i=1, lim do
			if logic.fileLruTab[i]~=nil then
				print(out.fileRecordToString(logic.fileLruTab[i]))
			else
				print()
			end
		end
	
		--stampo la tabella dei socket acceduti recentemente
		print(string.format("\n%-21s %-21s %-4s %-6s (%-s,%-s)", "local", "remote", "prot", "role", "r", "w"))
		for i=1, lim do
			if logic.socketLruTab[i]~=nil then
				print(out.socketRecordToString(logic.socketLruTab[i]))
			else
				print()
			end
		end
	end,


	--[[
		Stampa sul terminale tutti i dati relativi a files
		e sockets ordinati dal più al meno utilizzato.
	--]]
	doLongOutput = function()
	
		local outFile = assert(io.open("scRep"..os.date("%X_%b.%d.%Y", os.time())..".txt", "w"))
		
		--pulisco il terminale
		io.write("\27[2J")
	
		--stampo il PID o il nome dell'exe
		if pid~=nil then
			mPrint(outFile, "PID: "..pid )
		else
			mPrint(outFile, "exe: "..exe )
		end
	
		--stampo la tabella dei files dal più al meno acceduto
		mPrint(outFile, "type\topen\tread\twrite\tname")
		local value = out.extractMax(logic.fileTab, out.comparator)
		while( value~=nil ) do
			mPrint(outFile, out.fileRecordToString(value))
			value = out.extractMax(logic.fileTab, out.comparator)
		end
	
		--stampo la tabella dei socket dal più al meno acceduto
		mPrint(outFile, string.format("\n%-21s %-21s %-4s %-6s (%-s,%-s)", "local", "remote", "prot", "role", "r", "w"))
		value = out.extractMax(logic.socketTab, out.comparator)
		while( value~=nil ) do
			mPrint(outFile, out.socketRecordToString(value))
			value = out.extractMax(logic.socketTab, out.comparator)
		end
		
		outFile:close()
	end	
}
