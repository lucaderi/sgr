-- Define the fields to be captured
local fields = {
    quic = Field.new("tls.quic.parameter.type"),    -- QUIC transport parameter type field
    tls = Field.new("tls.handshake.extension.type") -- TLS extension type field
}

-- Define the fields for IP address and port
local f_ip_src = Field.new("ip.src")        -- Source IP address field
local f_ip_dst = Field.new("ip.dst")        -- Destination IP address field
local f_port_src = Field.new("udp.srcport") -- Source port field
local f_port_dst = Field.new("udp.dstport") -- Destination port field

-- Define the lookup tables for TLS extensions and transport parameters
local lookup_tls_extensions = {
    ["43"] = true, -- supported_versions
    ["51"] = true  -- key_share
}

local lookup_transport_parameters = {
    -- ["0x0"] = true, --  original_destination_connection_id	
    -- ["0x1"] = true, --	max_idle_timeout	
    -- ["0x2"] = true, --  stateless_reset_token	
    ["0x3"] = true, --	max_udp_payload_size	
    ["0x4"] = true, --	initial_max_data	
    -- ["0x5"] = true, --	initial_max_stream_data_bidi_local	
    ["0x6"] = true, --	initial_max_stream_data_bidi_remote	
    ["0x7"] = true, --	initial_max_stream_data_uni	
    ["0x8"] = true, --	initial_max_streams_bidi	
    -- ["0x9"] = true, --	initial_max_streams_uni	
    ["0xa"] = true, --	ack_delay_exponent	
    ["0xb"] = true, --	max_ack_delay	
    ["0xc"] = true, --	disable_active_migration	
    -- ["0xd"] = true, --	preferred_address	
    -- ["0xe"] = true, --	active_connection_id_limit	
    ["0xf"] = true, --	initial_source_connection_id	
    -- ["0x10"] = true, --	retry_source_connection_id	
}

-- Micro-db for known QUIC fingerprints
local known_fingerprints = {
    ["43_51-0x6_0x7_0x4_0x8_0x3_0xb_0xc_0xf"] = "quic-go",
    ["51_43-0xf_0x7_0x4"] = "ngtcp2",
    ["43_51-0x6_0x7_0x4_0x8_0xa_0x3_0xf"] = "mvfst",
    ["51_43-0x3_0x4_0x6_0x7_0x8_0xa_0xb_0xc_0xf"] = "quiche",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xa_0xb_0xf"] = "kwik",
    ["51_43-0x4_0x8_0x3_0x6_0x7_0xb_0xf"] = "picoquic",
    ["51_43-0x4_0x6_0x7_0x8_0xa_0xb_0xf"] = "aioquic",
    ["43_51-0x3_0x4_0x6_0x7_0xa_0xb_0xf"] = "msquic",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xc_0xf"] = "xquic",
    ["51_43-0x4_0x7_0x8_0xf"] = "lsquic",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xf"] = "quinn",
    ["43_51-0x4_0x6_0x7_0x8_0xf"] = "s2n-quic",
    ["43_51-0x3_0x4_0x6_0x7_0xc_0xf"] = "go-x-net"
}

local known_fingerprints_sorted = {
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xf"] = "chrome",
    ["51_43-0x3_0x4_0x6_0x7_0x8_0xf"] = "chrome",
    ["51_43-0x4_0x6_0x7_0x8_0xb_0xc_0xf"] = "neqo"
}

-- Create a table to store the clients' fingerprints
local clients = {}

-- Initialize the output string for the text window
local output = "Nessun handshake QUIC trovato."

-- Create a variable for the text window
local tw = nil

-- Function to refresh the text window
local function updateWindow()
    if tw then tw:set(output) end
end

-- Function to convert field info to string
local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

-- Create a new protocol for registering a post-dissector
local proto = Proto("quic_fingerprint", "QUIC FP")

-- Create a field for the fingerprint
local fingerprint_field = ProtoField.string("quic_fingerprint.str", "Fingerprint QUIC")
local guess_field = ProtoField.string("quic_fingerprint.library", "Libreria QUIC")
proto.fields = { fingerprint_field, guess_field }

-- Function to add a fingerprint to the window
local function addFingerprint(flow, fingerprint, guess)
    clients[flow] = { fingerprint, guess }
    output = "Fingerprints QUIC trovati:\n\n\n"
    for fl, fp in pairs(clients) do
        output = output ..
            string.format("-\t%s\n \tFingerprint: %s\n \t%s\n",
                fl, fp[1], #fp[2] > 0 and "Possibili librerie: " or "Nessuna libreria rilevata.")
        for _, g in ipairs(fp[2]) do
            output = output .. string.format(" \t- %s\n", g)
        end
        output = output .. "\n"
    end
    updateWindow()
end

-- The dissector function callback
function proto.dissector(tvb, pinfo, tree)
    local fingerprint = { {}, {} }
    for name, field in pairs(fields) do
        local values = { field() }
        if #values == 0 then return end
        for _, value in ipairs(values) do
            if name == "tls" then
                value = tostring(value)
                if lookup_tls_extensions[value] then
                    table.insert(fingerprint[1], value)
                end
            elseif name == "quic" then
                value = string.format("0x%x", tostring(value))
                if lookup_transport_parameters[value] then
                    table.insert(fingerprint[2], value)
                end
            end
        end
    end
    if #fingerprint[1] == 0 or #fingerprint[2] == 0 then return end

    -- Create a string representation of the fingerprint
    local fingerprint_str = table.concat(fingerprint[1], "_") .. "-" .. table.concat(fingerprint[2], "_")

    -- Sort the transport parameters
    table.sort(fingerprint[2])
    local fingerprint_str_sorted = table.concat(fingerprint[1], "_") .. "-" .. table.concat(fingerprint[2], "_")

    -- Guess the libraries
    local guesses = {}
    table.insert(guesses, known_fingerprints[fingerprint_str])
    table.insert(guesses, known_fingerprints_sorted[fingerprint_str_sorted])

    -- Add the fingerprint to the dissection tree
    local fingerprint_tree = tree:add(proto):set_generated()
    fingerprint_tree:add(fingerprint_field, fingerprint_str):set_generated()
    fingerprint_tree:add(guess_field, #guesses > 0 and table.concat(guesses, ", ") or "sconosciuta"):set_generated()

    -- Add the fingerprint to the window
    local flow = string.format("%s:%s -> %s:%s", getstring(f_ip_src()), getstring(f_port_src()), getstring(f_ip_dst()),
        getstring(f_port_dst()))
    addFingerprint(flow, fingerprint_str, guesses)
end

-- Register the protocol as a post-dissector
register_postdissector(proto)

-- Create a menu function to display the fingerprints in a text window
local function menu_view_tree()
    tw = TextWindow.new("QUIC Fingerprint")
    tw:set_atclose(function() tw = nil end)
    updateWindow()
end

-- Add the menu function to the Tools submenu
if gui_enabled() then
    register_menu("QUIC Fingerprint/Mostra fingerprints", menu_view_tree, MENU_TOOLS_UNSORTED)
end
