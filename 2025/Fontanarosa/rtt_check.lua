
-- Script in Lua per Wireshark che confronta l'RTT TCP o ICMP misurato con l'RTT medio del paese di origine dell'IP sorgente, basato sui dati di MaxMind

--##################################################

-- Mappatura dei continenti , esclusa l'antartica, in base a latitudine e longitudine ( approssimativa ) 
local continent_bounds = {

    ["Africa"] = {lat_min = -35, lat_max = 35, lon_min = -20, lon_max = 52},
    ["Europe"] = {lat_min = 35, lat_max = 70, lon_min = -25, lon_max = 52},
    ["Asia"] = {lat_min = -8, lat_max = 76, lon_min = 52, lon_max = 180},
    ["Oceania"] = {lat_min = -55, lat_max = -8, lon_min = 110, lon_max = 180},
    ["North-America"] = {lat_min = 13, lat_max = 70, lon_min = -170, lon_max = -50},
    ["South-America"] = {lat_min = -56, lat_max = 13, lon_min = -80, lon_max = -30}

}

-- Funzione per determinare il continente in base alla latitudine e longitudine
local function get_continent(lat, lon)

    for continent, bounds in pairs(continent_bounds) do
        
        if lat > bounds.lat_min and lat <= bounds.lat_max and lon >= bounds.lon_min and lon < bounds.lon_max then
            return continent
        end

    end

    return "Unknown"  -- Se non rientra in nessuna delle aree definite

end

--##################################################

-- Funzione per leggere un file txt e creare la struttura rtt_reference
function create_rtt_reference(file_path)

    local rtt_reference = {}
    local file = io.open(file_path, "r")
    -- Errore in Wireshark
    if not file then
        error("File non trovato: " .. file_path)
    end

    -- Leggi ogni riga del file
    for line in file:lines() do
        -- Dividi la riga in campi separati dalla virgola
        local country_code, mean, stddev = line:match("([^,]+),([^,]+),([^,]+)")
        -- Per i dati validi
        if country_code and mean and stddev then

            rtt_reference[country_code] = {
                mean = tonumber(mean),     -- Converti il mean in numero
                stddev = tonumber(stddev)  -- Converti lo stddev in numero
            }

        end
    end

    file:close()
    return rtt_reference

end

-- Default è il percorso di Wireshark
local file_path = "ntp_rtt_stats.txt"
local rtt_reference = create_rtt_reference(file_path)

--for country_code, data in pairs(rtt_reference) do
--    print(country_code, data.mean, data.stddev)
--end

-- Funzione per determinare il paese con l'RTT medio più vicino
local function estimate_response_country(rtt)

    local best_match = "Unknown"
    local min_difference = math.huge
    
    for country, stats in pairs(rtt_reference) do

        local diff = math.abs(rtt - stats.mean)
        if diff < min_difference then
            min_difference = diff
            best_match = country
        end

    end
    
    return best_match

end

--##################################################

-- Creazione del protocollo Proto(short_name, long_name)
local rtt_checker = Proto("RTTCheck", "RTT Anomaly Detector")

-- Campi Wireshark per le operazione del protocollo
local o_rtt_tcp = Field.new("tcp.analysis.ack_rtt")         -- campo per l'rtt nei pacchetti TCP / TLS
local o_icmp_resptime = Field.new("icmp.resptime")          -- campo per l'rtt nei pacchetti ICMP

-- Prendiamo i campi source poiché quelli source or destination potrebbero contenere + valori e non servono
local o_geoip_src = Field.new("ip.geoip.src_country_iso")   -- campo per codice ISO della nazione
local o_geoip_lon = Field.new("ip.geoip.src_lon")           -- campo per longitugine della nazione
local o_geoip_lat = Field.new("ip.geoip.src_lat")           -- campo per latitudine della nazione

--##################################################

-- Post-Dissector che lavora per ICMP e TCP
function rtt_checker.dissector(buffer, pinfo, tree)

    local icmp_resptime = o_icmp_resptime() and o_icmp_resptime().value

    if icmp_resptime then
        -- Converti il valore NSTime in stringa e poi in numero
        icmp_resptime = tostring(icmp_resptime)  -- Converti NSTime in stringa
        icmp_resptime = tonumber(icmp_resptime)  -- Converti stringa in numero
        icmp_resptime = icmp_resptime            -- In millisecondi
    end

    local rtt_tcp = o_rtt_tcp() and o_rtt_tcp().value

    if rtt_tcp then
        rtt_tcp = tostring(rtt_tcp)
        rtt_tcp = tonumber(rtt_tcp)
        rtt_tcp = rtt_tcp * 1000
    end

    local rtt_value = rtt_tcp or icmp_resptime

    if rtt_value then

        --print("icmp_resptime:", icmp_resptime)
        --print("rtt_value:", rtt_value)
        local country = o_geoip_src() and tostring(o_geoip_src().value)
        local lat = o_geoip_lat() and tonumber(o_geoip_lat().value)
        local lon = o_geoip_lon() and tonumber(o_geoip_lon().value)
        
        if country and lat and lon then

            local mean = -1
            local stddev
            local threshold_upper = 0
            local threshold_lower = math.huge
            local continent = "Unknown"
            local estimated_country = estimate_response_country(rtt_value) 

            if rtt_reference[country] then

                mean = rtt_reference[country].mean
                stddev = rtt_reference[country].stddev
                
                -- I valori soglia sono 2 volte la deviazione standard
                threshold_upper = mean + (2 * stddev)  -- Soglia superiore
                threshold_lower = mean - (2 * stddev)  -- Soglia inferiore

            else continent = get_continent(lat, lon) end

            if rtt_reference[continent] then

                mean = rtt_reference[continent].mean
                stddev = rtt_reference[continent].stddev
                threshold_upper = mean + (2 * stddev)
                threshold_lower = mean - (2 * stddev)

            end

            -- Se non ho nè country nè continente => visualizza Unknown
            if (rtt_value > threshold_upper or rtt_value < threshold_lower) and estimated_country ~= country then
 
                local subtree = tree:add(rtt_checker, "RTT Anomaly"):set_generated()
                subtree:add("Detected country: ", country):set_generated()
                subtree:add("Expected RTT: ", string.format("%f ms", mean)):set_generated()
                subtree:add("Measured RTT: ", string.format("%f ms", rtt_value)):set_generated()
                subtree:add("Estimated country: ", estimated_country):set_generated()
                subtree:add_expert_info(expert.group.PROTOCOL, expert.severity.ERROR, "RTT mismatch detected")

            end
        end
    end
end

--##################################################

-- Registrazione del protocollo come post-dissector
register_postdissector(rtt_checker)

-- Funzione che visualizza la tabella di riferimento RTT
local function menu_view_reference_rtt()
    -- Finestra di testo con titolo
    local win = TextWindow.new("RTT Reference Table")
    -- Intestazione della finestra
    win:append("=== RTT Reference Values by Country & Continent ===\n\n")
    -- Intestazione delle colonne
    win:append(string.format("  %-16s  %-15s  %-15s\n", "Country", "Mean RTT (ms)", "StdDev (ms)"))
    win:append(string.rep("-", 52) .. "\n")
    for country, stats in pairs(rtt_reference) do
        -- Dati di ogni paese mostrando la media e la deviazione standard
        win:append(string.format("  %-16s  %-15.2f  %-15.2f\n", country, stats.mean, stats.stddev))
    end

end

-- Registra l'elemento di menu sotto "RTT" con il nome "Visualizza Tabella di Riferimento"
-- Viene eseguita la funzione 'menu_view_reference_rtt'
-- register_menu(stringa, funzione, where)
register_menu("RTT/View RTT Reference Table", menu_view_reference_rtt, MENU_TOOLS_UNSORTED)

--##################################################
