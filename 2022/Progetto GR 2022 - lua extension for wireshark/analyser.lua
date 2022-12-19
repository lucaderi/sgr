--[[
Questo plug-in Lua per wireshark aiuta nell'analisi del livello trasporto, evidenziando gli host che potrebbero avere problemi.

Per la parte TCP vengono sfruttati i campi calcolati da wireshark, mentre per la parte UDP viene mantenuta una struttura dati e viene fatta una stima dei flussi.
In particolare, viene mantenuta una struttura dati, che mantiene le informazioni di tutti gli host, e degli host con cui comunicano.

in modo analogo per icmp. in particolare verranno evidenziati i messaggi di tipo Destination unreachable e time exceeded in base alla tabella https://resources.infosecinstitute.com/topic/icmp-protocol-with-wireshark/ https://resources.infosecinstitute.com/wp-content/uploads/1-319.png

Lo scopo di questo plugin è coadiuvare i professionisti it dando loro uno strumento che automatizza l'analisi di una traccia, evidenziando informazioni che potrebbero essere estratte manualmente applicando filtri, richiedendo molto più tempo.
Si consiglia, qualora vengano evidenziati dei possibili problemi nell'analisi, di verificare la traccia ed i pacchetti coinvolti.
]]
local function main_analyser()
	
	-- Declare the window we will use
	local tw = TextWindow.new("L4 analyser");
	tw:set("avvio plug-in\n");
	tw:append ("elaborazione in corso...\n");

	-- this is our tap
	--A Listener is called once for every packet that matches a certain filter or has a certain tap.
	local tap = Listener.new();
	
	-- inizializzazione delle strutture dati.  Le strutture sono delle tabelle che vengono utilizzate per memorizzare i dati rilevanti in modo da stamparli in un secondo momento
	tcp_data = {};
	udp_data = {};
	icmp_data = {};
	
	
	
	--this is a function to remove the tap
	local function remove()
		-- this way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end
	-- we tell the window to call the remove() function when closed
	tw:set_atclose(remove)

	-- this function will be called once for each packet
	--As per doc, is possible to define a packet function associated to a listner (tap) object that will be called (from wireshark engine) once every packet matches the Listener listener filter.
	--When later called by Wireshark, the packet function will be given:
	--A Pinfo object
	--A Tvb object
	--A tapinfo table
	function tap.packet(pinfo,tvb)
		--ottengo il fieldinfo tcp
		local tcp = tcp_f ();
		
		if (tcp) then --se esiste per il pacchetto corrente
			local tcp_stream = tostring(tcp_stream_f().value); --estraggo lo stream
			
			--estraggo gli ip
			local ipsrc = ipsrc_f();
			local ipdst = ipdst_f();
			
			if (tcp_data[tcp_stream]) then --se ho già informazioni per lo stream

			else --altrimenti aggiungo i dati per lo stream
				local tcp_completeness = tcp_completeness_f(); --estraggo le informazioni sulla completezza della connessione tcp
				--estraggo le porte
				local tcp_srcport = tcp_srcport_f ();
				local tcp_dstport = tcp_dstport_f ();
				--creo un'entry nella tabella. memorizzo i valori dei fieldinfo, in quanto dopo l'esecuzione del listener gli oggetti non saranno più disponibili
				tcp_data[tcp_stream] = {ip_srg=ipsrc.value, ip_dst=ipdst.value,port_srg =tcp_srcport.value, port_dst = tcp_dstport.value, completeness = tcp_completeness.value, direction_dup_ack =0, direction_retransmission = 0, reverse_dup_ack =0, reverse_retransmission = 0}
				
				--[[
				tw:append ("lunghezza tcp_data: " .. #tcp_data .. "\n");
				l'operatore # ritorna la lunghezza di tabelle che hanno come indici valori interi. per tabelle che fungono da dizionari/tabelle has o si contano volta volta con un for, oppure si mantiene un campo che memorizza la dimensione e si aggiorna man mano con la struttura dati
				]]
			end
			
			local tcp_analysis_top = tcp_analysis_top_f();
			if (tcp_analysis_top) then --se il pacchetto ha informazioni sull'analisi tcp
				local tcp_analysis_dup = tcp_analysis_dup_f();
				if (tcp_analysis_dup) then -- se c'è un ack duplicato
					if (tcp_data[tcp_stream]["ip_srg"] == ipsrc.value) then -- se la direzione del pacchetto è "la direzione dello stream"
						tcp_data[tcp_stream]["direction_dup_ack"] = tcp_data[tcp_stream]["direction_dup_ack"] +1; -- incrementa il contatore
					else
						tcp_data[tcp_stream]["reverse_dup_ack"] = tcp_data[tcp_stream]["reverse_dup_ack"] +1; -- altrimenti, incrementa il contatore della direzione opposta
					end
				end
				local tcp_analysis_retran = tcp_analysis_retran_f();
				if (tcp_analysis_retran) then -- se c'è una ritrasmissione
					if (tcp_data[tcp_stream]["ip_srg"] == ipsrc.value) then -- se la direzione del pacchetto è "la direzione dello stream"
						tcp_data[tcp_stream]["direction_retransmission"] = tcp_data[tcp_stream]["direction_retransmission"] +1; -- incrementa il contatore
					else
						tcp_data[tcp_stream]["reverse_retransmission"] = tcp_data[tcp_stream]["reverse_retransmission"] +1; -- altrimenti, incrementa il contatore della direzione opposta
					end
				end
			end
		else --altrimenti ottengo il fieldinfo icmp
			local icmp = icmp_f ();
			if (icmp) then --se esiste per il pacchetto corrente
				local ipsrc = ipsrc_f();
				local ipdst = ipdst_f();
				
				local icmp_type = icmp_type_f ();
				--TODO: da implementare
			else --altrimenti ottengo il fieldinfo udp - cercando udp solo se non c'è icmp, prevengo i pacchetti icmp che incapsulano datagrammi
				--[[
				per le connessioni udp viene mantenuta una tabella, il cui indice è la quadrupla <ip sorgente, porta sorgente, ip destinazione, porta destinazione>.
				quando arriva un nuovo pacchetto si verifica se esiste la relativa connessione, se non esiste, si verifica che non esista la connessione inversa, in tal caso si marca la presenza di una risposta sulla connessione.
				]]
				local udp = udp_f();
				if (udp) then --se esiste per il pacchetto corrente
					local ipsrc = ipsrc_f();
					local ipdst = ipdst_f();
					local udp_srcport = udp_srcport_f ();
					local udp_dstport = udp_dstport_f ();
					--calcolo la chiave della connessione di cui fa parte il datagramma						
					local key = ByteArray.new();
					key:append ((ipsrc.tvb):bytes());
					key:append ((udp_srcport.tvb):bytes());
					key:append ((ipdst.tvb):bytes());
					key:append ((udp_dstport.tvb):bytes());
					key = tostring(key);
					
					if (udp_data[key]) then --se esistono già dati per la connessione corrente
						udp_data[key]["datagram"]=udp_data[key]["datagram"]+1; --aggiorno il contatore
					else --altrimenti cerco il ritorno della connessione
						local reverse_key = ByteArray.new();
						reverse_key:append ((ipdst.tvb):bytes());
						reverse_key:append ((udp_dstport.tvb):bytes());
						reverse_key:append ((ipsrc.tvb):bytes());
						reverse_key:append ((udp_srcport.tvb):bytes());
						reverse_key = tostring(reverse_key);

						if (udp_data[reverse_key]) then --se esistono già dati per la connessione corrente
							udp_data[reverse_key]["reverse_datagram"]=udp_data[reverse_key]["reverse_datagram"]+1; --aggiorno il contatore
							udp_data[reverse_key]["reply"]=true;
						else --altrimenti, se non sono ancora stati registrati pacchetti per questa connessione
							--inserisco i dati nella struttura. i dati sempre con la prima chiave calcolata
							udp_data[key] = {ip_srg=ipsrc.value, ip_dst=ipdst.value,port_srg =udp_srcport.value, port_dst = udp_dstport.value, reply = false, datagram = 0; reverse_datagram=0};
						end
						--[[oss: si potrebbe non memorizzare i valori di porte e ip nella struttura, e ricavarli dalla chiave volta volta]]
					end
				end
			end 
		end
	end

	-- this function will be called once every few seconds to update our window
	--from doc: A function that will be called once every few seconds to redraw the GUI objects; in TShark this funtion is called only at the very end of the capture file.
	--When later called by Wireshark, the draw function will not be given any arguments.
--	function tap.draw(t)
	function tap.draw()
		--tw:clear()

		--tw:append(ip .. "\t" .. num .. "\n");
		tw:append ("draw\n");
		tw:append ("TCP\n");
		for index, value in pairs(tcp_data) do --per ogni dato inserito (usa pairs perché è una tabella con indici non numerici che fa dizionario)
			tw:append (tostring(index)..": " .. "\n"); --stampa l'indice
			for deep_index, deep_value in pairs(value) do
				tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
			end
			tw:append ("\n");
		end
		
		tw:append ("\nUDP\n");
		for index, value in pairs(udp_data) do --per ogni dato inserito (usa pairs perché è una tabella con indici non numerici che fa dizionario)
			tw:append (tostring(index)..": " .. "\n"); --stampa l'indice
			for deep_index, deep_value in pairs(value) do
				tw:append ("\t" .. tostring (deep_index) .. ": " .. tostring (deep_value) .. "\n");
			end
			tw:append ("\n");
		end
		
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		tcp_data = {};
		udp_data = {};
		icmp_data ={};
	end

	-- Ensure that all existing packets are processed.
	--doc: Rescans all packets and runs each tap listener without reconstructing the display.
	retap_packets()
end

-- Create the menu entry
register_menu("Lua L4 analyser",main_analyser,MENU_TOOLS_UNSORTED)

--variabili locali per i campi a cui si è interessati

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

icmp_f = Field.new('icmp');
icmp_type_f = Field.new('icmp.type');

	
-- Notify the user that the menu was created
if gui_enabled() then
   local splash = TextWindow.new("Hello!");
   splash:set("Wireshark has been enhanced with a usefull feature.\n")
   splash:append("Go to 'Tools->Lua L4 analyser' and check it out!")
   
end