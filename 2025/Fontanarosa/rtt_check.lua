
-- Script in Lua per Wireshark che confronta l'RTT TCP o ICMP misurato con l'RTT medio del paese di origine dell'IP sorgente, basato sui dati di MaxMind

--##################################################

-- Mappatura dei continenti in base a latitudine e longitudine ( approssimativa ) 
local continents = {

    ["Oceania"] = {
        {-11.88, 110}, {33.13, 140}, {-5, 165}, {-5, 180},
        {-52.5, 180}, {-52.5, 142.5}, {-31.88, 110}
    },
    ["Antarctica"] = {
        {-60, -180}, {-60, 180}, {-90, 180}, {-90, -180}
    },
    ["Africa"] = {
        {15, -30}, {28.25, -13}, {35.42, -10}, {38, 10},
        {33, 27.5}, {31.74, 34.58}, {29.54, 34.92},
        {27.78, 34.46}, {11.3, 44.3}, {12.5, 52},
        {-60, 75}, {-60, -30}
    },
    ["Europe"] = {
        {90, -10}, {90, 77.5}, {42.5, 48.8}, {42.5, 30},
        {40.79, 28.81}, {41, 29}, {40.55, 27.31}, {40.4, 26.75},
        {40.05, 26.36}, {39.17, 25.19}, {35.46, 27.91}, {33, 27.5},
        {38, 10}, {35.42, -10}, {28.25, -13}, {15, -30},
        {57.5, -37.5}, {78.13, -10}
    },
    ["North-America"] = {
        {90, -168.75}, {90, -10}, {78.13, -10}, {57.5, -37.5},
        {15, -30}, {15, -75}, {1.25, -82.5}, {1.25, -105},
        {51, -180}, {60, -180}, {60, -168.75}
    },
    ["South-America"] = {
        {1.25, -105}, {1.25, -82.5}, {15, -75}, {15, -30},
        {-60, -30}, {-60, -105}
    },
    ["Asia"] = {
        {90, 77.5}, {42.5, 48.8}, {42.5, 30}, {40.79, 28.81},
        {41, 29}, {40.55, 27.31}, {40.4, 26.75}, {40.05, 26.36},
        {39.17, 25.19}, {35.46, 27.91}, {33, 27.5}, {31.74, 34.58},
        {29.54, 34.92}, {27.78, 34.46}, {11.3, 44.3}, {12.5, 52},
        {-60, 75}, {-60, 110}, {-31.88, 110}, {-11.88, 110},
        {33.13, 140}, {51, 166.6}, {60, 180},
        {90, 180}
    }
}

-- Funzione che verifica se un punto (lat, lon) è dentro un poligono definito dai suoi vertici -> Algoritmo di Ray-Casting
-- L'idea di base è quella di tracciare una linea orizzontale ( parallela all'asse delle X ) dal punto in questione
-- e contare quante volte questa linea interseca i lati del poligono. Se il numero di intersezioni è dispari, il punto è all'interno del poligono; se è pari, è all'esterno
function is_point_in_polygon(point, polygon)

    local x, y = point[1], point[2]  -- Estrae latitudine (x) e longitudine (y) dal punto
    local n = #polygon               -- Numero di vertici del poligono
    local inside = false             -- Variabile che terrà traccia se il punto è dentro il poligono o no

    -- Itera su ogni lato del poligono
    for i = 1, n do

        local x1, y1 = polygon[i][1], polygon[i][2]                      -- Vertice iniziale del lato
        local x2, y2 = polygon[(i % n) + 1][1], polygon[(i % n) + 1][2]  -- Vertice finale del lato che alla fine sarà l'ultimo lato del poligono

        -- Controlla se il punto si trova tra i due vertici in latitudine (y)
        if (y1 > y) ~= (y2 > y) then
            -- Calcola la longitudine del punto di intersezione tra il lato e la linea orizzontale che passa per `y`
            local x_intersection = (y - y1) * (x2 - x1) / (y2 - y1) + x1

            -- Se il punto si trova alla sinistra della linea di intersezione (x < x_intersection),
            -- invertiamo il valore di `inside` ( true / false ) per determinare se il punto è dentro il poligono
            if x < x_intersection then
                inside = not inside
            end
        end
    end

    -- Restituisce true se il punto è dentro il poligono, false altrimenti
    return inside
end

-- Funzione che restituisce il nome del continente in cui si trova il punto
function get_continent(point, continents)
    -- Itera su ogni continente e il relativo poligono
    for continent, polygon in pairs(continents) do
        -- Se il punto è dentro il poligono del continente
        if is_point_in_polygon(point, polygon) then
            -- print(continent)
            -- print("\n\n")
            return continent  -- Restituisce il nome del continente
        end
    end

    return "Unknown"  -- Se nessun poligono contiene il punto, restituisce "Unknown"
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

-- Determina il separatore di directory in base al sistema operativo
local separator = package.config:sub(1,1)  -- '/' su Unix-like, '\' su Windows
local file_path = Dir.personal_plugins_path() .. separator .. "ntp_rtt_stats.txt"
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

        --print("country, mean, diff: ",country, stats.mean, diff)

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
            local used_country

            -- Se il paese non è presente, useremo il continente
            if not rtt_reference[country] then

                local point = {lat, lon}
                continent = get_continent(point, continents)

            end

            if rtt_reference[country] then used_country = country else used_country = continent end

            if rtt_reference[used_country] then

                mean = rtt_reference[used_country].mean
                stddev = rtt_reference[used_country].stddev

                -- I valori soglia sono 2 volte la deviazione standard
                threshold_upper = mean + (2 * stddev)  -- Soglia superiore
                threshold_lower = mean - (2 * stddev)  -- Soglia inferiore

            end

            -- Se non ho nè country nè continente => visualizza Unknown
            if (rtt_value > threshold_upper or rtt_value < threshold_lower) and estimated_country ~= used_country then
 
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
