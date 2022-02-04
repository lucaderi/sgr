-- Parametri:
--             host
--             community


dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path
require "lua_utils"


sendHTTPHeader('text/html; charset=iso-8859-1')

ntop.dumpFile(dirs.installdir .. "/httpdocs/inc/header.inc")
dofile(dirs.installdir .. "/scripts/lua/inc/menu.lua")





community = _GET["community"]
host      = _GET["host"]
oid       = "1.3.6.1.2.1"

sysName     = '1.3.6.1.2.1.1.5.0'      	   -- Nome del sistema
sysDescr    = '1.3.6.1.2.1.1.1.0'   	      -- Descrizione del sistema
sysUpTime   = '1.3.6.1.2.1.1.3.0'	         -- Tempo dall'avvio del sistema

ifDescr     = '1.3.6.1.2.1.2.2.1.2'				-- Description
ifOperStatus= '1.3.6.1.2.1.2.2.1.8' 		   -- Stato
ifInOctets  = '1.3.6.1.2.1.2.2.1.10'			-- Byte in
ifOutOctets = '1.3.6.1.2.1.2.2.1.16' 	      -- Byte out
ifPhysAddr  = '1.3.6.1.2.1.2.2.1.6'			   -- MAC
ifSpeed     = '1.3.6.1.2.1.2.2.1.5'			   -- Speed


nextDescr      = ifDescr..'.1'
nextOperStatus = ifOperStatus..'.1'
nextInOctets   = ifInOctets..'.1'
nextOutOctets  = ifOutOctets..'.1'
nextPhysAddr   = ifPhysAddr..'.1'
nextSpeed      = ifSpeed..'.1'


i= 1
finish= false



if ((community == nil) or (host == nil) or (oid == nil) or (community == '') or (host == '') or (oid == '')) then
   print ('<strong>BAD PARAMETERS</strong>')
   return
end


print('Host: '..host..'<br>')
print('Community: '..community..'<br>')
print('Object Identifier: '..oid ..'<br><br>')


print('<strong><abbr>System information</abbr></strong>')
print('<br></br>')
print('<table class="table table-bordered table-striped">\n')


-- Stampo il sysName
rsp = ntop.snmpget(host, community, sysName)
if (rsp~=nil) then
   for k, v in pairs(rsp) do
      print('<tr><th width=35%>SysName</th><td colspan=2>'..v..'</td></tr>\n')
   end
end

-- Stampo il sysContact
rsp = ntop.snmpget(host, community, sysDescr)
if (rsp~=nil) then
   for k, v in pairs(rsp) do
      print ('<tr><th width=35%>SysDescr</th><td colspan=2>'..v..'</td></tr>\n')
   end
end

-- Stampo il sysUpTime
rsp = ntop.snmpget(host, community, sysUpTime)
if (rsp ~= nil) then
   for k, v in pairs(rsp) do
      print ('<tr><th width=35%>SysUptime</th><td colspan=2>'..v..'</td></tr>\n')
   end
end

-- Chiudo la tabella
print('</table><br />')




-- Stampo, per ogni interfaccia, le info:
--                   (1) Nome interfaccia    -- ifDescr
--                   (2) Stato               -- ifOperStatus
--                   (3) Byte in             -- ifInOctets
--                   (4) Byte out            -- ifOutOctets
--                   (5) MAC                 -- ifPhysAddr
--                   (6) Speed               -- ifSpeed



rispDescr		= ntop.snmpget (host, community, nextDescr)
rispOperStatus = ntop.snmpget (host, community, nextOperStatus)
rispInOctets	= ntop.snmpget (host, community, nextInOctets)
rispOutOctets  = ntop.snmpget (host, community, nextOutOctets)
rispPhysAddr   = ntop.snmpget (host, community, nextPhysAddr)
rispSpeed      = ntop.snmpget (host, community, nextSpeed)



while (not(finish)) do

	-- Controllo se devo terminare
	if (rispDescr ~= nil) then
		for k, v in pairs (rispDescr) do
			if (not(string.find (k, ifDescr))) then
				dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")
				return

			end
		end
	end

   print ('<table class="table table-bordered table-striped">')

	-- ***** --
	-- Stampo ifDescr
	-- ***** --
	if (rispDescr ~= nil) then
		for k, v in pairs (rispDescr) do
			if (v ~= '') then
				print ('<tr><th width=35%>ifDescr</th><td colspan=2>'..v..'</td></tr>\n')
			else
				print ('<tr><th width=35%>ifDescr</th><td colspan=2>Unknown</td></tr>\n')
			end
			nextDescr= k
		end
	else
		print ('<tr><th width=35%>ifDescr</th><td colspan=2>Unknown</td></tr>\n')
		nextDescr= ifDescr..'.'..i
	end


	-- ***** --
	-- Stampo ifOperStatus
	-- ***** --
	if (rispOperStatus ~= nil) then
		for k, v in pairs (rispOperStatus) do
			if (v == '1') then
				print ('<tr><th width=35%>ifOperStatus</th><td colspan=2>On</td></tr>\n')
			else
				print ('<tr><th width=35%>ifOperStatus</th><td colspan=2>Off</td></tr>\n')
			end
			nextOperStatus= k
		end
	else
		print ('<tr><th width=35%>ifOperStatus</th><td colspan=2>Unknown</td></tr>\n')
		nextOperStatus= ifOperStatus..'.'..i
	end


	-- ***** --
	-- Stampo ifInOctets
	-- ***** --
	if (rispInOctets ~= nil) then
		for k, v in pairs (rispInOctets) do
			if (v ~= '') then
				print ('<tr><th width=35%>ifInOctets</th><td colspan=2>'..v..'</td></tr>\n')
			else
				print ('<tr><th width=35%>ifInOctets</th><td colspan=2>Unknown</td></tr>\n')
			end
			nextInOctets= k
		end
	else
		print ('<tr><th width=35%>ifInOctets</th><td colspan=2>Unknown</td></tr>\n')
		nextInOctets= ifInOctets..'.'..i
	end


	-- ***** --
	-- Stampo ifOutOctets
	-- ***** --
	if (rispOutOctets ~= nil) then
		for k, v in pairs (rispOutOctets) do
			if (v ~= '') then
				print ('<tr><th width=35%>ifOutOctets</th><td colspan=2>'..v..'</td></tr>\n')
			else
				print ('<tr><th width=35%>ifOutOctets</th><td colspan=2>Unknown</td></tr>\n')
			end
			nextOutOctets= k
		end
	else
		print ('<tr><th width=35%>ifOutOctets</th><td colspan=2>Unknown</td></tr>\n')
		nextOutOctets= ifOutOctets..'.'..i
	end


	-- ***** --
	-- Stampo ifPhysAddr
	-- ***** --
	if (rispPhysAddr ~= nil) then
		for k, v in pairs (rispPhysAddr) do
			if (v ~= '') then
				print ('<tr><th width=35%>ifPhysAddr</th><td colspan=2>'..v..'</td></tr>\n')
			else
				print ('<tr><th width=35%>ifPhysAddr</th><td colspan=2>Unknown</td></tr>\n')
			end
			nextPhysAddr= k
		end
	else
		print ('<tr><th width=35%>ifPhysAddr</th><td colspan=2>Unknown</td></tr>\n')
		nextPhysAddr= ifPhysAddr..'.'..i
	end


	-- ***** --
	-- Stampo ifSpeed
	-- ***** --
	if (rispSpeed ~= nil) then
		for k, v in pairs (rispSpeed) do
			if (v ~= '') then
				print ('<tr><th width=35%>ifSpeed</th><td colspan=2>'..v..'</td></tr>\n')
			else
				print ('<tr><th width=35%>ifSpeed</th><td colspan=2>Unknown</td></tr>\n')
			end
			nextSpeed= k
		end
	else
		print ('<tr><th width=35%>ifSpeed</th><td colspan=2>Unknown</td></tr>\n')
		nextSpeed= ifSpeed..'.'..i
	end


	-- Richiedo i valori dei successivi OID
	i= i+1
	rispDescr= ntop.snmpgetnext (host, community, nextDescr)
	rispOperStatus= ntop.snmpgetnext (host, community, nextOperStatus)
	rispInOctets= ntop.snmpgetnext (host, community, nextInOctets)
   rispOutOctets= ntop.snmpgetnext (host, community, nextOutOctets)
	rispPhysAddr= ntop.snmpgetnext (host, community, nextPhysAddr)
	rispSpeed= ntop.snmpgetnext (host, community, nextSpeed)

	print ('</table>')
	print ('<br/><br/>')
end

dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")
