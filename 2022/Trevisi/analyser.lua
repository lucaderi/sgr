--[[
Questo plug-in Lua per wireshark è pernsato per i professionisti del settore, che si trovano ad analizzare segnalazioni degli utenti di interruzioni di servizio o generci disservizi presumibilmente legati alla rete. Lo scopo è evidenziare (scremare) la mole di dati catturati evidenziando degli host/comunicazioni potenzialmente problematici, da cui partire con analisi più puntuali ed approfondite.

Per la parte TCP vengono sfruttati i campi calcolati da wireshark, mentre per la parte UDP viene fatta una stima dei flussi.
Analogamente per i messaggi icmp si cerca di riscotruire l'andamento delle comunicazione degli host coinvolti. Verranno analizzati i messaggi di error report in base alla tabella https://resources.infosecinstitute.com/topic/icmp-protocol-with-wireshark/ https://resources.infosecinstitute.com/wp-content/uploads/1-319.png
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000oMQp
Ricordiamo che un error message report viene mandato quando si verifica un qualche errore, e contiene il pacchetto che ha generato l'errore, anche se questo non era una richiesta icmp.
]]
local function main_analyser()
	
	-- Dichiarazione della finestra che verrà utilizzata
	local tw = TextWindow.new("L4 analyser");

	-- Questo è il nostro rubinetto
	--un Listener viene chiamato una volta per ogni pacchetto che matcha un certo filtro del rubinetto. Nel nostro caso non sono impostati filtri, quindi tutti i pacchetti matcheranno.
	local tap = Listener.new();
	
	-- inizializzazione delle strutture dati.  Le strutture sono delle tabelle che vengono utilizzate per memorizzare i dati rilevanti all'analisi. In seguito potranno essere summarizzati e stampati
	tcp_data = {};
	udp_data = {};
	icmp_data = {};
	
	local print_for_verbose = false;
	local print_for_deep_debug = false;
	
	--definisce la stampa dei dati nella finestra
	local function print_all ()		
		local data = {}; --raggruppo in un'unica struttura i dati che rappresentano delle situazioni di possibile errore
		--la struttura avrà come chiave la combinazione di ip sorgente ed ip destinazione 
		
		--elaboro la struttura tcp
		if (print_for_verbose or print_for_deep_debug) then
			tw:append ("TCP\n");
		end
		for index, value in pairs(tcp_data) do --per ogni dato inserito, value è volta volta il record inserito--> l'array tcp
			--[[ uno degli strumenti usati per valutare la connessione tcp è la completeness.
			in particolare, wireshark associa un valore di completeness in base a vari stati:
			1 : SYN
			2 : SYN-ACK
			4 : ACK
			8 : DATA
			16 : FIN
			32 : RST
			una conversazione completa con scambio dati avrà quindi completeness pari a 31(SYN + SYN-ACK + ACK + DATA + FIN) o 63(SYN + SYN-ACK + ACK + DATA + FIN + RST)
			--> allo scopo di questo tool, lo scambio dati non è essenziale per valutare la conversazione (la connessione potrebbe essere aperta e chiusa senza alcuno scambio dati,
			ma ciò non indicherebbe necessariamente un problema di connessione. pertanto anche 23 (SYN + SYN-ACK + ACK + FIN) e 55 (SYN + SYN-ACK + ACK + FIN + RST) non verranno considerati con indicatori di problemi.
			--> una completeness di 47(SYN + SYN-ACK + ACK + DATA + RST), verrà invece conteggiata, in quanto potrebbe indicare un qualche problema di chiusura forzata con RST
			prima della naturale fine della sessione applicativa.
			https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html]]
			local add = false;
			local outgoing = false;
			local ingoing = false;
			local key;
			local tcpkey;
			local incomplete = -1;
			local srgString = tostring(value["ip_srg"]);
			local dstString = tostring(value["ip_dst"]);
			if (srgString < dstString) then
				key = srgString .. dstString;
			else
				key = dstString .. srgString;
			end
			if (value["port_srg"] < value["port_dst"]) then
				tcpkey = tostring(value["port_srg"]) .. tostring(value["port_dst"]);
			else
				tcpkey = tostring(value["port_dst"]) .. tostring(value["port_srg"]);
			end
			
			if (value["completeness"] ~= 31 and value["completeness"] ~= 63 and value["completeness"] ~= 23 and value["completeness"] ~= 55 and value["completeness"] ~= 47) then
				incomplete = value["completeness"];
			end
			if ((value["direction_dup_ack"] >0) or (value["direction_retransmission"]>0)) then --ho problemi da ip_srg a ip_dst
				outgoing=true;
			end
			if ((value["reverse_dup_ack"] >0) or (value["reverse_retransmission"]>0)) then
				ingoing=true;
			end
			
			
			if (incomplete or outgoing or ingoing) then --se devo aggiornare la struttura data
				if (data[key]) then --se ho già dati per questi ip
					if (not data[key]["tcp"][tcpkey]) then --ma non per questa conversazione tcp
						local tcpvet;
						if (data[key]["ip_srg"] == srgString) then
							tcpvet = {port_srg=value["port_srg"], port_dst=value["port_dst"], outbound=outgoing, inbound=ingoing, incomplete = incomplete};
						else
							tcpvet = {port_srg=value["port_dst"], port_dst=value["port_srg"], outbound=ingoing, inbound=outgoing, incomplete = incomplete};
						end
						data[key]["tcp"][tcpkey]=tcpvet;
					end
					if (data[key]["ip_srg"] == srgString) then
						data[key]["tcp"][tcpkey]["outbound"]= outgoing;
						data[key]["tcp"][tcpkey]["inbound"]= ingoing;
					else
						data[key]["tcp"][tcpkey]["outbound"]= ingoing;
						data[key]["tcp"][tcpkey]["inbound"]= outgoing;
					end
					data[key]["tcp"][tcpkey]["incomplete"]= incomplete;
				else --lo aggiungo -- la direzione è quella del flusso tcp che sto analizzando
					local tcpvet = {};
					tcpvet[tcpkey] = {port_srg=value["port_srg"], port_dst=value["port_dst"], outbound=outgoing, inbound=ingoing, incomplete = incomplete};
					data[key]={ip_srg=srgString,ip_dst=dstString, tcp=tcpvet, udp={}, icmp=false, reverse_icmp=false};
				end
				add = true;
			end
				
				
			if (print_for_deep_debug or (print_for_verbose and add))then
				tw:append (tostring(index)..": " .. "\n"); --stampa l'indice
				for deep_index, deep_value in pairs(value) do
					tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
				end
				tw:append ("\n");
			end
		end
		
		--elaboro la struttura udp
		if (print_for_verbose or print_for_deep_debug) then
			tw:append ("UDP\n");
		end
		for index, value in pairs(udp_data) do --per ogni dato inserito (usa pairs perché è una tabella con indici non numerici che fa dizionario)
			local add = false;
			local outgoing = false;
			local ingoing = false;
			local outgoing_icmp = false;
			local ingoing_icmp=false;
			local key;
			local udpkey;
			local srgString = tostring(value["ip_srg"]);
			local dstString = tostring(value["ip_dst"]);
			if (srgString < dstString) then
				key = srgString .. dstString;
			else
				key = dstString .. srgString;
			end
			if (value["port_srg"] < value["port_dst"]) then
				udpkey = tostring(value["port_srg"]) .. tostring(value["port_dst"]);
			else
				udpkey = tostring(value["port_dst"]) .. tostring(value["port_srg"]);
			end
			--[[ per udp non si possono fare molte assunzioni, quindi ci limiteremo a considerare un possibile problema l'assenza di pacchetti in una delle due direzioni, e riportare eventuali mancate consegne segnalate da icmp
			]]
			if (value["datagram"] == 0) then 
				outgoing=true;
			end
			if (value["icmp"]) then
				outgoing_icmp = true;
			end
			if (value["reverse_datagram"] ==0 ) then
				ingoing=true;
			end
			if (value["reverse_icmp"]) then
				ingoing_icmp = true;
			end
			
			if (outgoing or ingoing or outgoing_icmp or ingoing_icmp) then
				if (data[key]) then
					if (data[key]["udp"][udpkey]) then
						if (data[key]["ip_srg"] == srgString) then
							data[key]["tcp"][udpkey]["outbound"]= outgoing;
							data[key]["tcp"][udpkey]["inbound"]= ingoing;
							data[key]["tcp"][udpkey]["outbound_icmp"]= outgoing_icmp;
							data[key]["tcp"][udpkey]["inbound_icmp"]= ingoing_icmp;
						else
							data[key]["tcp"][udpkey]["outbound"]= outgoing;
							data[key]["tcp"][udpkey]["inbound"]= ingoing;
							data[key]["tcp"][udpkey]["outbound_icmp"]= outgoing_icmp;
							data[key]["tcp"][udpkey]["inbound_icmp"]= ingoing_icmp;
						end
					else
						local udpvet;
						if (data[key]["ip_srg"] == srgString) then
							udpvet = {port_srg=value["port_srg"], port_dst=value["port_dst"], outbound=outgoing, inbound=ingoing, outbound_icmp=outgoing_icmp, inbound_icmp=ingoing_icmp}
						else
							udpvet = {port_srg=value["port_srg"], port_dst=value["port_dst"], outbound=ingoing, inbound=outgoing, outbound_icmp=ingoing_icmp, inbound_icmp=outgoing_icmp}
						end
						data[key]["udp"][udpkey]=udpvet;
					end
				else
					local udpvet = {};
					udpvet[udpkey]={port_srg=value["port_srg"], port_dst=value["port_dst"], outbound=outgoing, inbound=ingoing, outbound_icmp=outgoing_icmp, inbound_icmp=ingoing_icmp};
					data[key]={ip_srg=srgString,ip_dst=dstString, tcp={}, udp=udpvet, icmp=false, reverse_icmp=false};
				end
				add = true;
			end
				
			if (print_for_deep_debug or (print_for_verbose and add))then
				tw:append (tostring(index)..": " .. "\n"); --stampa l'indice
				for deep_index, deep_value in pairs(value) do
					tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
				end
				tw:append ("\n");
			end
		end
		
		--elaboro la struttura icmp
		if (print_for_verbose or print_for_deep_debug) then
			tw:append ("ICMP\n");
		end
		for index, value in pairs(icmp_data) do --per ogni dato inserito (usa pairs perché è una tabella con indici non numerici che fa dizionario)
			--[[per i messaggi icmp, qualora sia stata fatta una richiesta e non si ha avuto una risposta (sia dall'analisi del plug-in, che dal campo no_resp di wireshark)
			si considera un'anomalia, così come se non è stata fatta una request icmp ma ci sono degli errori.
			qualora invece sia stata fatta una request icmp e si ha una reply, indipendentemente dall'aver ricevuto errori, non si considera un'anomalia
			]]
			if ((value["request"] and ((not value["reply"]) or value["no_resp"])) or ((not value["request"]) and value["err"]) or not (value["request"] and value["reply"]))then
				--[[ciascun record di icmp_data mantiene le informazioni per un verso della conversazione. la chiave di data è sempre ordinata]]
				if (value["ip_srg"] < value["ip_dst"]) then
					key = value["ip_srg"] .. value["ip_dst"];
				else
					key = value["ip_dst"] .. value["ip_srg"];
				end
				
				if (not data[key])then
				 --se non ho ancora i dati per questi interlocutori
					data[key] = {ip_srg=value["ip_srg"],ip_dst=value["ip_dst"], tcp={}, udp={}, icmp=false, reverse_icmp=false};
				end
				if (value["ip_srg"]==data[key]["ip_srg"]) then 
					data[key]["icmp"]=true;
				else
					data[key]["reverse_icmp"]=true;
				end
				add=true;				
			end
			if (print_for_deep_debug or (print_for_verbose and add))then
				tw:append (tostring(index)..": " .. "\n"); --stampa l'indice
				for deep_index, deep_value in pairs(value) do
					tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
				end
				tw:append ("\n");
			end
		end
		
		--stampa il contenuto della struttura data completa, senza che sia ancora stata sintetizzata
		if (print_for_deep_debug or print_for_verbose)then
			tw:append ("questi sono i dati grezzi per i quali sono state rilevate anomalie: " .. "\n");
			for index, value in pairs(data) do
				tw:append (tostring(index)..": " .. "\n"); --l'indice di data
				for deep_index, deep_value in pairs(value) do
					if (deep_index ~= "tcp" and  deep_index ~= "udp") then -- i campi di data
						tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
					else
						tw:append ("\t" .. tostring(deep_index)..": " .. "\n"); --il nome della struttura interna (udp o tcp)
						for ddin, ddv in pairs(deep_value) do
							tw:append ("\t\t" .. tostring(ddin)..": " .. "\n"); --la chiave della struttura interna
							for dddin, dddv in pairs(ddv) do
								tw:append ("\t\t\t" .. tostring (dddin) .. ": " .. tostring (dddv) .. "\n"); --i valori della struttura interna
							end
						end
					end
				end
			end
			tw:append ("\n");
		end
		
		tw:append ("queste sono le comunicazioni soggette a anomalie\nCompletezza TCP: 1 : SYN - 2 : SYN-ACK - 4 : ACK - 8 : DATA - 16 : FIN - 32 : RST\n");
		--si aggregano ulteriormente i dati e se ne stampa un sunto sintentico
		for index, value in pairs(data) do
			tw:append (value["ip_srg"] .. " " .. value["ip_dst"] .. "\n");
			for i, v in pairs(value["tcp"]) do
				tw:append ("\ttcp " .. tostring(v["port_srg"]) .. " " .. tostring(v["port_dst"]) .. " ");
				if (v["outbound"]) then
					tw:append ("->" .. " ");
				end
				if (v["inbound"]) then
					tw:append ("<- ");
				end
				if (v["incomplete"]>-1) then
					tw:append ("| incomplete " .. v["incomplete"]);
				end
				tw:append ("\n");
			end
			for i, v in pairs(value["udp"]) do
				tw:append ("\tudp " .. tostring(v["port_srg"]) .. " " .. tostring(v["port_dst"]) .. " ");
				if (v["outbound"]) then
					tw:append ("-> no pkt ");
				end
				if (v["inbound"]) then
					tw:append ("<- no pkt ");
				end
				if (v["outbound_icmp"]) then
					tw:append ("| -> icmp ");
				end
				if (v["inbound_icmp"]) then
					tw:append ("| <- icmp");
				end
				tw:append ("\n");
			end
			if (value["icmp"] or value["reverse_icmp"]) then
				tw:append ("\ticmp ");
				if (value["icmp"]) then
					tw:append ("->" .. " ");
				end
				if (value["reverse_icmp"]) then
					tw:append ("<-");
				end
				tw:append ("\n");
			end
			tw:append ("\n");
		end
		
	end
	
	--questa funzione rimuove il tap
	local function remove()
		-- in questo modo viene rimosso l'oggetto listner che altrimenti resterebbe in esecuzione indefinitamente
		tap:remove();
	end
	
	-- impostiamo la finestra affinché invochi il metoro remove() alla sua chiusura
	tw:set_atclose(remove)
	
	--definisce una funzione che cambia la modalità di debug ed aggiorna la finestra con il nuovo output
	local function flip_verbose_mode() 
		print_for_verbose = true;
		print_for_deep_debug = false;
		tw:clear();
		print_all();
	end
	
	local function flip_deep_debug_mode() 
		print_for_deep_debug = true;
		print_for_verbose = false;
		tw:clear();
		print_all();
	end
	
	local function normal_mode() 
		print_for_deep_debug = false;
		print_for_verbose = false;
		tw:clear();
		print_all();
	end
	
	--si aggiungono i bottoni all'interfaccia
	tw:add_button("Verbose", flip_verbose_mode) -- aggiungo un bottone alla finestra per stampare un output completo
	tw:add_button("Deep_Debug", flip_deep_debug_mode)
	tw:add_button("Normal output", normal_mode)
	
	
	
	-- Questa funzione viene chiamata una volta per ciascun pacchetto del rubinetto
	-- è possibile definire una funzione packet associata ad un oggetto listener (rubinetto) che verrà chiamata (dal motore di wireshark) una volta ogni volta che un pacchetto matcha il filtro di uno specifico rubinetto.
	--quando wireshark chiamerà la funzione gli passerà (opzionalmente):
	--un oggetto Pinfo
	--un oggetto Tvb object
	--una tabella tapinfo
	function tap.packet(pinfo,tvb)
		local eth_ig = eth_ig_f();
		local ipsrc = ipsrc_f();
		local ipdst = ipdst_f();
		if (((eth_ig) and (not eth_ig.value)) and (ipsrc and ipdst and ((((ipsrc.range):uint()) ~= 0) and (((ipdst.range):uint()) ~= 0)))) then 
		--i pacchetti non ipv4, quelli da/per indirizzi multicast/broadcast , o aventi host 0.0.0.0, non vengono analizzati
			
			local icmp = icmp_f (); --ottengo il field info icmp.
			local tcp = tcp_f ();-- ottengo il fieldinfo tcp
				
			--[[ dato che i pacchetti icmp di error reporting contengono nel campo data i primi byte del pacchetto che ha dato origine all'errore, e che i campi,
			p.e. udp, tcp, ecc vengono popolati anche con i byte qui contenuti, per evitare erronee interpretazioni, ci assicuriamo sempre che i pacchetti non siano di tipo icmp
			]]
			if (tcp and not icmp) then --se il pacchetto corrente contiene il campo tcp e non quello icmp
				local tcp_stream = tcp_stream_f();
				--estraggo gli ip
				
				if (tcp_stream and ipsrc and ipdst) then -- se i campi contengono valori
					local stream = tostring(tcp_stream.value); --estraggo lo stream

					if (not tcp_data[stream]) then --se non ho già informazioni per lo stream
					--aggiungo il record nella struttura dati
						local tcp_completeness = tcp_completeness_f(); --estraggo le informazioni sulla completezza della connessione tcp
						--estraggo le porte
						local tcp_srcport = tcp_srcport_f ();
						local tcp_dstport = tcp_dstport_f ();
						if (tcp_completeness and tcp_srcport and tcp_dstport) then
							--creo un'entry nella tabella. memorizzo i valori dei fieldinfo, in quanto dopo l'esecuzione del listener gli oggetti non saranno più disponibili
							tcp_data[stream] = {ip_srg=ipsrc.value, ip_dst=ipdst.value,port_srg =tcp_srcport.value, port_dst = tcp_dstport.value, completeness = tcp_completeness.value, direction_dup_ack =0, direction_retransmission = 0, reverse_dup_ack =0, reverse_retransmission = 0}
						end
					end
					
					if (tcp_data[stream]) then -- controllo ipocondriaco --> fallisce solo se al passo precedente non è stato aggiunto il dato per campi con informazioni incomplete
						local tcp_analysis_top = tcp_analysis_top_f();
						if (tcp_analysis_top) then --se il pacchetto ha informazioni sull'analisi tcp
							local tcp_analysis_dup = tcp_analysis_dup_f();
							if (tcp_analysis_dup) then -- se c'è un ack duplicato
								if (tcp_data[stream]["ip_srg"] == ipsrc.value) then -- se la direzione del pacchetto è "la direzione dello stream"
									tcp_data[stream]["direction_dup_ack"] = tcp_data[stream]["direction_dup_ack"] +1; -- incrementa il contatore
								else
									tcp_data[stream]["reverse_dup_ack"] = tcp_data[stream]["reverse_dup_ack"] +1; -- altrimenti, incrementa il contatore della direzione opposta
								end
							end
							local tcp_analysis_retran = tcp_analysis_retran_f();
							if (tcp_analysis_retran) then -- se c'è una ritrasmissione
								if (tcp_data[stream]["ip_srg"] == ipsrc.value) then -- se la direzione del pacchetto è "la direzione dello stream"
									tcp_data[stream]["direction_retransmission"] = tcp_data[stream]["direction_retransmission"] +1; -- incrementa il contatore
								else
									tcp_data[stream]["reverse_retransmission"] = tcp_data[stream]["reverse_retransmission"] +1; -- altrimenti, incrementa il contatore della direzione opposta
								end
							end
						end
					end
				end
			else --altrimenti ottengo il fieldinfo udp - cercando udp solo se non c'è icmp, prevengo i pacchetti icmp che incapsulano datagrammi
				--[[
				per le connessioni udp viene mantenuta una tabella, il cui indice è una quadrupla ordinata degli ip e delle porte, allo scopo di questa analisi pacchetti che provengono da un certo host1:porta1 e diretti ad un altro host2:porta2, e quelli che coinvolgono gli stessi host:porta switchati in sorgente e destinazione verranno considerati appartenenti alla medesima connessione.
				quando arriva un nuovo pacchetto si verifica se esiste la relativa connessione, quindi si guarda la direzione e si marca la presenza di un datagramma su di essa.
				]]
				local udp = udp_f();
				if (udp and not icmp) then --se esiste udp per il pacchetto corrente e non è icmp
					local udp_srcport = udp_srcport_f ();
					local udp_dstport = udp_dstport_f ();
					local rtp = rtp_f();
					
					
					if (ipsrc and ipdst and udp_dstport and udp_srcport) then --se i campi di indirizzi e porte contengono valori
						local ordered_key ="";
						if (tostring(ipsrc.value) < tostring(ipdst.value)) then
							ordered_key = tostring(ipsrc.value) .. tostring(ipdst.value);
						else
							ordered_key= tostring(ipdst.value) .. tostring(ipsrc.value);
						end
						
						if (udp_srcport.value < udp_dstport.value) then
							ordered_key = ordered_key .. tostring (udp_srcport.value) .. tostring(udp_dstport.value);
						else
							ordered_key = ordered_key .. tostring (udp_dstport.value) .. tostring(udp_srcport.value);
						end
						if (not rtp) then --il protocollo rtp è un protocollo noto per essere unidirezionale, quindi, in generale, non mi aspetto un flusso di ritorno - ignoro i pacchetti di questo tipo, dato che sarà sempre e comunque unidirezionale -- wireshark mette a disposizione altri strumenti per l'analisi del traffico voip
							if (not udp_data[ordered_key]) then --se non esistono già dati per la connessione corrente inserisco i dati nella struttura. 
								--calcolo quanti pacchetti per direzione, per sapere se vi è stata una risposta basterà confrontare il valore di reverse_datagram se è maggiore di 0
								udp_data[ordered_key] = {ip_srg=ipsrc.value, ip_dst=ipdst.value,port_srg =udp_srcport.value, port_dst = udp_dstport.value, datagram = 0; reverse_datagram=0, icmp = false, reverse_icmp=false};
							end
							if (udp_data[ordered_key]["ip_srg"] == ipsrc.value) then
								udp_data[ordered_key]["datagram"]=udp_data[ordered_key]["datagram"]+1; --aggiorno il contatore
							else -- è la risposta
								udp_data[ordered_key]["reverse_datagram"]=udp_data[ordered_key]["reverse_datagram"]+1; --aggiorno il contatore
							end
						end
					end
				else
					if (icmp) then --se esiste per il pacchetto corrente
						local icmp_type = icmp_type_f ();
						local icmp_resp = icmp_resp_f ();
						local echo = false;
						local echo_reply = false;
						
						if (icmp_type) then --se c'è il campo icmp_type
							local key = nil;
							local proto = nil;
							local icmpTvbRange;
							
							--[[la chiave della struttura è la combinazione di ip sorgente e destinazione degli host coinvolti nella comunicazione.
							dato che in caso di errore riesco ad ottenere i byte, e quindi riscotruire gli ip. (la loro rappresentazione come stringa. potrei ottenere direttamente un oggetto Address e invocare il suo metodo tostring, ma la stampa dipende dalle impostazioni di wireshark sulla risoluzione o meno degli indirizzi, pertanto questa rappresentazione potrebbe non essere univoca - hint: un dns che viene risolto con più ip)
							]]
							
							if (icmp_type.value == 3 or icmp_type.value == 4 or icmp_type.value == 5 or icmp_type.value == 11 or icmp_type.value == 12) then -- è un messaggio di errore
								icmpTvbRange = icmp.range; --recupera il tvb corrispondente al campo icmp (è escluso l'header ip che incapsula il pacchetto)
							
								--[[il contenuto del campo icmp contiene 1 byte per la codifica del tipo, 1 byte per la codifica del codice, 2 byte per il checksum, e 4 byte per il puntatore all'elemento che ha causato il problema. i successivi byte contengono i primi byte del pacchetto che ha originato l'errore. --> in caso di ipv4 contiene, tra le altre cose, l'header ip del pacchetto originario, da cui si possono ricavare gli ip coinvolti nella comunicazione.
								https://www.techtarget.com/searchnetworking/definition/ICMP
								i primi 8 byte del messaggio icmp contengono le informazioni del protocollo, quindi c'è l'header ip del pacchetto originario.
								i primi 12 byte contengono informazioni per il protocollo ip, quindi ci sono i 4 byte dell'indirizzo sorgente, e poi i 4 byte della destinazione
								https://techhub.hpe.com/eginfolib/networking/docs/routers/msrv5/cg/5200-2309_acl-qos-cg/content/462306048.htm

								dato che i pacchetti di error report vengono mandati anche dai router per segnalare un qualche problema; qualora il pacchetto di origine sia
								un datagramma udp aggiungiamo il recordo alla rispettiva struttura - L'analisi degli errori icmp è l'unico mezzo
								che abbiamo per capire se ci sono stati dei problemi nella consegna del datagramma, fuori dal livello applicativo
								]]
								local origProtoTvbRange = icmpTvbRange:range(17, 1);
								proto = origProtoTvbRange:uint();
								if (proto and (proto ==17)) then --l'and torna false se il primo operando è false, senza valutare il secondo. 
								
								--[[se il messaggio che ha dato origine all'errore è di tipo udp, significa che il pacchetto che lo ha generato è già passato, ed ho già creato 
								il relativo record nella struttura udp data. se non ho creato il record, al fine di questo tool, il pacchetto verrà ignorato - ndr non ci interessano errorri di pacchetti non sono oggetto della cattura]]
									local origSrcTvbRange = (icmpTvbRange:range(20, 4)):bytes();
									local destSrcTvbRange = (icmpTvbRange:range(24, 4)):bytes();
									local udp = udp_f();
									if (udp) then
										local udp_srcport = udp_srcport_f();
										local udp_dstport = udp_dstport_f();
										if (udp_srcport and udp_dstport) then
											local h1 = tostring (origSrcTvbRange:get_index(0)) .. "." ..tostring (origSrcTvbRange:get_index(1)) .. "." ..tostring (origSrcTvbRange:get_index(2)) .. "." ..tostring (origSrcTvbRange:get_index(3));
											local h2 = tostring (destSrcTvbRange:get_index(0)) .. "." ..tostring (destSrcTvbRange:get_index(1)) .. "." ..tostring (destSrcTvbRange:get_index(2)) .. "." ..tostring (destSrcTvbRange:get_index(3));
											if (h1 < h2) then
												key = h1 .. h2;
											else
												key = h2 .. h1;
											end
											--la chiave della struttura udp è ordinata, quindi finisco di costruirla
											if (udp_srcport.value < udp_dstport.value) then
												key = key .. tostring (udp_srcport.value) .. tostring(udp_dstport.value);
											else
												key = key .. tostring (udp_dstport.value) .. tostring(udp_srcport.value);
											end
											
											if (udp_data[key]) then --aggiorno la struttura solo se contiene già dati per questa conversazione
												if (h1 == tostring(udp_data[key]["ip_srg"])) then
													udp_data[key]["icmp"] = true;
												else
													udp_data[key]["reverse_icmp"] = true;
												end	
											end
										end
									end
								else -- se c'è un errore ed il pacchetto che l'ha originato non è udp aggiungo i dati alla struttura icmp
									local origSrcTvbRange = (icmpTvbRange:range(20, 4)):bytes();
									local destSrcTvbRange = (icmpTvbRange:range(24, 4)):bytes();
									local h1 = tostring (origSrcTvbRange:get_index(0)) .. "." ..tostring (origSrcTvbRange:get_index(1)) .. "." ..tostring (origSrcTvbRange:get_index(2)) .. "." ..tostring (origSrcTvbRange:get_index(3));
									local h2 = tostring (destSrcTvbRange:get_index(0)) .. "." ..tostring (destSrcTvbRange:get_index(1)) .. "." ..tostring (destSrcTvbRange:get_index(2)) .. "." ..tostring (destSrcTvbRange:get_index(3));
									key = h1 .. h2;
									
									if (not icmp_data[key]) then --se icmp[key] non esite è nil. I condizionali considerano nil e false come falso, e qualsiasi altro valore true
										icmp_data[key] = {ip_srg=h1, ip_dst=h2, no_resp = false, request = false, reply = false, err = true};
									else --altrimenti aggiorno i valori
										icmp_data[key]["err"] = true;
									end
								end
							else --altrimenti se non è un errore
								if (icmp_type.value == 8) then --se era una richiesta gli ip coinvolti sono effettivamenti quelli del pacchettto ip che incapsula l'icmp
									ipsrc = ipsrc_f();
									ipdst = ipdst_f();
									echo = true;
								else --altrimenti se è una risposta devo guardare la conversazione inversa
									if (icmp_type.value == 0) then
										ipsrc = ipdst_f();
										ipdst = ipsrc_f();
										echo_reply = true;
									end
								end
								if (ipsrc and ipdst) then
									key = tostring(ipsrc.value) .. tostring(ipdst.value);
									if (not icmp_data[key]) then --se icmp[key] non esite è nil. I condizionali considerano nil e false come falso, e qualsiasi altro valore true
										icmp_data[key] = {ip_srg=tostring(ipsrc.value), ip_dst=tostring(ipdst.value), no_resp = false, request = echo, reply = echo_reply, err = false};
									else --altrimenti aggiorno i valori
										icmp_data[key]["request"] = icmp_data[key]["request"] or echo;
										icmp_data[key]["reply"] = icmp_data[key]["reply"] or echo_reply;
									end
									
									if (icmp_resp) then --ho il campo icmp_resp solo per richieste icmp
										icmp_data[key]["no_resp"] = true;
									end
								end
							end
						end
					end
				end	
			end 
		end
	end

	-- questa funzione viene chiamata per aggiornare il contenuto della finestra
	function tap.draw()
		print_all();
	end

	function tap.reset()
		tw:clear()
		tcp_data = {};
		udp_data = {};
		icmp_data ={};
	end

	retap_packets()
end

-- Crea una entry nel menù di wireshark
register_menu("Lua L4 analyser",main_analyser,MENU_TOOLS_UNSORTED)

--variabili globali per i campi a cui si è interessati
eth_frame_number_f = Field.new('frame.number');
tcp_syn_f = Field.new('tcp.flags.syn');
tcp_ack_f = Field.new('tcp.flags.ack');
tcp_ack_number_f = Field.new('tcp.ack_raw');
tcp_seq_number_f = Field.new('tcp.seq_raw');


ipsrc_f = Field.new('ip.src');
ipdst_f = Field.new('ip.dst');

tcp_f = Field.new('tcp');
tcp_completeness_f = Field.new('tcp.completeness');
tcp_srcport_f = Field.new('tcp.srcport');
tcp_dstport_f = Field.new('tcp.dstport');
tcp_stream_f = Field.new('tcp.stream');
tcp_analysis_top_f = Field.new('tcp.analysis');
tcp_analysis_dup_f = Field.new('tcp.analysis.duplicate_ack');
tcp_analysis_retran_f = Field.new('tcp.analysis.retransmission');

udp_f = Field.new('udp');
udp_srcport_f = Field.new('udp.srcport');
udp_dstport_f = Field.new('udp.dstport');
udp_stream_f = Field.new('udp.stream');
rtp_f = Field.new('rtp');

icmp_f = Field.new('icmp');
icmp_type_f = Field.new('icmp.type');
icmp_resp_f = Field.new('icmp.no_resp');

eth_ig_f = Field.new('eth.ig');

	
-- notifica che è stata aggiunta una nuova voce ai menù
if gui_enabled() then
   local splash = TextWindow.new("Hello!");
   splash:set("Wireshark has been enhanced with a usefull feature.\n")
   splash:append("Go to 'Tools->Lua L4 analyser' and check it out!")
end
