#!/usr/bin/env python3

import re
import os
import shutil
import sys
import subprocess

import json
import urllib.request

# Detect dispositivo
OS_RULES = [
    # Mobile Apple
    (r'\b(iPhone|iPad|iPod)\b', "iOS (\\1)"),
    (r'\biOS\b', "iOS"),

    # Desktop Apple
    (r'\b(MacBook|Macintosh|Mac_?OS|Darwin)\b', "macOS"),

    # Android & Google
    (r'\b(Android|Pixel|Galaxy|MIUI|OnePlus|HarmonyOS)\b', "Android (\\1)"),

    # Microsoft Windows
    (r'\b(Windows NT 10\.0|Windows 11|Windows 10)\b', "Windows 10/11"),
    (r'\b(Windows NT 6\.[1-3]|Windows [78])\b', "Windows 7/8"),
    (r'\bWindows\b', "Windows"),

    # Linux / Embedded / IoT
    (r'\b(Ubuntu|Debian|Fedora|CentOS|Arch|Raspberry|Tizen)\b', "Linux (\\1)"),
    (r'\bLinux\b', "Linux")
]

def deduce_os(block, tcp_fingerprint_os):
    ua_match = re.search(r'\[User-Agent:\s*([^\]]+)\]', block)
    user_agent = ua_match.group(1) if ua_match else ""

    plain_match = re.search(r'\[PLAIN TEXT \(([^)]+)\)\]', block)
    plain_text = plain_match.group(1) if plain_match else ""

    sni_match = re.search(r'\[Hostname/SNI:\s*([^\]]+)\]', block)
    hostname = sni_match.group(1) if sni_match else ""

    l7_text_aggregate = f"{user_agent} {plain_text} {hostname}"

    for pattern, label in OS_RULES:
        match = re.search(pattern, l7_text_aggregate, re.IGNORECASE)
        if match:
            if "\\1" in label:
                return label.replace("\\1", match.group(1))
            return label

    if tcp_fingerprint_os and tcp_fingerprint_os != "Unknown":
        return tcp_fingerprint_os

    return "Unknown"

def run_ndpi_reader(pcap_path, output_txt_path, ndpi_bin: str = "ndpiReader") -> None:
    """ Esegue ndpiReader a riga di comando sul file pcapng e salva l'output su file .txt """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"File PCAP non trovato: '{pcap_path}'")

    # Verifica se l'eseguibile ndpiReader esiste o è nel PATH
    bin_path = shutil.which(ndpi_bin)
    if not bin_path:
        # Controlla percorso comune
        common_path = os.path.expanduser("~/nDPI/example/ndpiReader")

        if os.path.isfile(common_path) and os.access(common_path, os.X_OK):
            bin_path = common_path

    if not bin_path:
        raise FileNotFoundError(
            f"Eseguibile '{ndpi_bin}' non trovato. Compilalo dentro nDPI/example/ o specificalo esplicitamente."
        )

    cmd = [bin_path, "-i", pcap_path, "-v", "2"]

    with open(output_txt_path, "w", encoding="utf-8") as out_file:
        result = subprocess.run(cmd, stdout=out_file, stderr=subprocess.PIPE, text=True, errors="ignore") # bloccante

    if result.returncode != 0 and result.stderr:
        raise RuntimeError(f"Errore durante l'esecuzione di ndpiReader:\n{result.stderr}")

def query_local_ai(prompt, kb_data, target_ip: str | None = None):
    url = "http://localhost:1234/v1/chat/completions"
    compacted_kb = {}

    hosts = kb_data.get("hosts", {})

    if target_ip and target_ip in hosts:
        #print("ENTRA")
        # kb fine grain per quell'host
        host_data = hosts[target_ip]
        compacted_kb[target_ip] = {
            "ja4": host_data.get("ja4"),
            "domains": host_data.get("domains"),
            "protocolli_app": host_data.get("protocolli_app"),
            "frequenza_app": host_data.get("frequenza_app"),
            "volume_byte_app": host_data.get("volume_byte_app"),
            "categorie": host_data.get("categorie"),
            "risks": host_data.get("risks"),
            "flow_list": host_data.get("flow_list"),
            "os_name": host_data.get("os_name")
        }
        scope_desc = f"L'utente sta analizzando specificamente l'host {target_ip}."
    else:
        # default --> kb generale
        for ip, host_data in hosts.items():
            compacted_kb[ip] = {
                "ip": ip,
                "os": host_data.get("os_name", "-"),
                "applicazioni": host_data.get("frequenza_app", {}).keys(),
                "tot_bye": sum(host_data.get("volume_byte_app", {}).values(), 0),
                "domini": host_data.get("domains", []),
                "tot_rischi": len(host_data.get("risks", {})),
                "categorie": host_data.get("categorie")
            }

        scope_desc = "Panoramica aggregata di rete: nessun host specifico selezionato."

    # Converto KB in stringa JSON e comprimo JSON togliendo spazi e a capo (Risparmiamo tantissimi token!)
    kb_compact = json.dumps(compacted_kb, separators=(',', ':'), default=list)

    system_context = f"""Sei un analista di rete e cybersecurity. {scope_desc}
                        Rispondi alle domande in modo conciso e mirato basandoti su questi dati nDPI: {kb_compact}.
                        Se l'utente ti chiede di ampliare l'analisi o servono correlazioni esterne, puoi farlo."""

    # Corpo della richiesta HTTP che verrà mandata al modello AI locale
    payload = {
        "model": "local-model",
        "messages": [
            {"role": "system", "content": system_context},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2 # Controlla quanto il modello deve essere variabile/creativo nella generazione della risposta
    }

    # Richiesta effettiva per il modello
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req) as response: #invio la richiesta HTTP al server locale, ed attendo la risposta
            result = json.loads(response.read().decode('utf-8')) # Converto la risposta in stringe e poi in un dict python
            return result["choices"][0]["message"]["content"] # prendo il testo { choices : [ { message: { role: ... , content: ... }}, ... ] }
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode('utf-8')
        return f"[-] Errore HTTP {e.code}: {error_msg}"
    except Exception as e:
        return f"[-] Errore di connessione a Bionic: {e}"

def verifica_mismatch_ja4_sni(flow_record):
    risks = []
    ja4_str = flow_record.get("ja4")
    sni_str = flow_record.get("sni")

    if not ja4_str:
        return risks

    prima_sezione = ja4_str.split('_')[0]

    # Il carattere in posizione [3]
    # Es. t13 d 1313h2 -> 'd' indica che è atteso un dominio
    if len(prima_sezione) >= 4:
        sni_strutturale = prima_sezione[3]

        # JA4 dice 'd' (dominio atteso), ma l'SNI testuale è assente o vuoto
        if sni_strutturale == 'd' and not sni_str:
            risks.append("JA4_SNI_MISMATCH: JA4 indica SNI con dominio, ma SNI testuale assente")

        # JA4 dice 'i' (IP diretto/Nessun SNI inviato), ma l'SNI testuale contiene un dominio
        elif sni_strutturale == 'i' and sni_str:
            risks.append("JA4_SNI_MISMATCH: JA4 indica nessun SNI (IP), ma è presente un SNI testuale")

    return risks

def parse_ndpi_output(file_path):
    if not os.path.exists(file_path):
        print(f"[Errore]: File '{file_path}' non trovato!")
        print("    Assicurati di aver generato il file con il comando (posizionato nella cartella contenente il file .pcqpng):")
        print("    /Users/<TUO_nome_user>/nDPI/example/ndpiReader -i ./traffico_telefono.pcapng -v 2 > ./ndpi_output.txt")
        print("    Oppure direttamente nella sezione di conversione PCAP/PCAPNG --> TXT con nDPI nel pannello laterale del Tool")
        sys.exit(1)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Uso i set() per mantenere gli elenchi senza duplicati (es. domini unici),
    # e i dizionari per memorizzare i contatori di frequenza.
    knowledge_base = {
        "durata_cattura": 0.0,
        "protocols": {}, # { protocollo: frequenza }
        "hosts": {}, # ip -> { ja4: set(), domains: set(), protocolli_app: set(), frequenza_app: dict(), frequenza_domini: dict(), volume_byte_app: dict(), categoria: dict() }
        "ja4_to_info": {},  # ja4 -> { domains: set(), L5_protocols: set(), hosts: set() } --> dove è stato osservato e a cosa è associato
        "all_domains": set(),  # insieme di tutti i domini unici osservati
        "all_risks": {},  # Dizionario globale di tutti i rischi rilevati
        "flows_list": []  # Lista lineare di TUTTI i flussi
    }

    # Prendo i protocolli
    flows = re.findall(r'\n\s*\d+\t(TCP|UDP|ICMP)', content)
    for protocol_L4 in flows:
        knowledge_base["protocols"][protocol_L4] = 0

    # Estraggo la durata della cattura del traffico
    duration_global_match = re.search(r'Traffic duration:\s+([\d.]+)\s+sec', content)
    if duration_global_match:
        durata_totale_pcap = float(duration_global_match.group(1))
        knowledge_base["durata_cattura"] = durata_totale_pcap

    flow_blocks = re.split(r'\n\s*(\d+)\t(TCP|UDP|ICMP|ICMPV6|DHCPV6)', content)

    idx = 1
    while idx < len(flow_blocks):
        flow_id = flow_blocks[idx]
        protocol_l4 = flow_blocks[idx + 1]
        block = flow_blocks[idx + 2]

        # Estrazione Protocollo L7/Applicazione riconosciuto da nDPI
        proto_app_match = re.search(r'\[Stack:\s*([^\]]+)\]', block)
        proto_app = proto_app_match.group(1) if proto_app_match else "Unknown"

        # Estrazione socket (SRC e DST)
        src_ip, src_port, dst_ip, dst_port = "", "", "", ""
        socket_match = re.search(r'(?:\[([0-9a-fA-F:]+)\]|([0-9.]+)):(\d+)\s*(<->|->)\s*(?:\[([0-9a-fA-F:]+)\]|([0-9.]+)):(\d+)', block)
        if socket_match:
            src_ip = socket_match.group(1) or socket_match.group(2)
            src_port = socket_match.group(3)

            dst_ip = socket_match.group(5) or socket_match.group(6)
            dst_port = socket_match.group(7)

        # Estrazione Categoria nDPI (es. Network, SocialNetwork, Web, ...)
        cat_match = re.search(r'\[cat:\s*([^/]+)/\d+\]', block)
        categoria = cat_match.group(1) if cat_match else "Unspecified"

        # Estrazione Breed nDPI (es: Fun, Acceptable, Safe, ...)
        breed_match = re.search(r'\[Breed:\s*([^\]]+)\]', block)
        breed = breed_match.group(1) if breed_match else "Unspecified"

        # Estrazione Dominio / SNI
        sni_match = re.search(r'\[Hostname/SNI:\s*([^\]]+)\]', block)
        hostname = sni_match.group(1) if sni_match else None

        # Estrazione JA4
        ja4_match = re.search(r'\[JA4:\s*([^\]]+)\]', block)
        ja4 = ja4_match.group(1) if ja4_match else None

        # Estrazione metadati TLS
        tls_ver_match = re.search(r'\[(TLSv1\.[0-3]|SSLv3)\]', block)
        tls_version = tls_ver_match.group(1) if tls_ver_match else "-"

        # Cipher Suite negoziata
        cipher_match = re.search(r'\[Cipher:\s*([^\]]+)\]', block)
        cipher_suite = cipher_match.group(1) if cipher_match else "-"

        # ALPN negoziato / annunciato
        alpn_match = re.search(r'\[(?:\(Advertised\)\s*)?ALPNs:\s*([^\]]+)\]', block)
        alpn_advertised = alpn_match.group(1) if alpn_match else "-"

        # Estrazione TCP Fingerprint --> SO
        os_match = re.search(r'\[TCP Fingerprint:\s*[^/]+/([^\]]+)\]', block)
        tcp_os = os_match.group(1) if os_match else "Unknown"
        os_name = deduce_os(block, tcp_os)

        # Estrazione Risk, Risk Info e Risk Score
        macro_risks = []
        risk_tag_match = re.search(r'\[Risk:\s*\*\*([^*]+)\*\*\]', block)
        if risk_tag_match:
            macro_risks = [r.strip() for r in re.split(r',', risk_tag_match.group(1)) if r.strip()]

        risk_details = []
        risk_info_match = re.search(r'\[Risk Info:\s*([^\]]+)\]', block)
        if risk_info_match:
            risk_details = [r.strip() for r in risk_info_match.group(1).split(';') if r.strip()]

        effective_risks = macro_risks if macro_risks else risk_details # Per i flussi in cui manca il tag [Risk:], uso solo Risk Info

        # Estrazione del testo completo dell'entropia (es. "Entropy: 7.857 (Encrypted or Random?)")
        entropy_val = ""
        entropy_match = re.search(r'\[Risk Info:[^\]]*?(Entropy:\s*[\d.]+(?:\s*\([^)]+\))?)', block, re.IGNORECASE)
        if entropy_match:
            entropy_val = entropy_match.group(1).strip()

        risk_score = "0"
        if effective_risks:
            risk_score = "0"  # valore di default per il risk score se nDPI non lo specifica
            score_match = re.search(r'\[Risk Score:\s*(\d+)\]', block)
            if score_match:
                risk_score = score_match.group(1)

        # Estrazione durata del flusso
        duration_sec = 0.0
        duration_str = "-"
        dur_match = re.search(r'\[(\d+(?:\.\d+)?)\s+sec\]', block)
        if dur_match:
            duration_sec = float(dur_match.group(1))
            duration_str = f"{duration_sec:.2f} s"
        elif "[< 1 sec]" in block:
            duration_sec = 0.001  # 1ms cosi che non danneggio troppo
            duration_str = "< 1 s"

        # Estrazione direzionalità del flusso
        direction = "Unknown"
        ratio_match = re.search(r'\[bytes ratio:\s*[-0-9.]+\s*\((Download|Upload|Mixed)\)\]', block)
        if ratio_match:
            direction = ratio_match.group(1)

        # Estrazione volume dati (Byte sent / recv)
        byte_match = re.search(r'\[\d+\s+pkts/(\d+)\s+bytes\s+(?:<->|->)\s+\d+\s+pkts/(\d+)\s+bytes\]', block)
        if byte_match:
            bytes_sent = int(byte_match.group(1))
            bytes_rcvd = int(byte_match.group(2))
            total_bytes = bytes_sent + bytes_rcvd
        else:
            bytes_sent = 0
            bytes_rcvd = 0
            total_bytes = 0

        # Throughput approssimativo (se durata > 0) (KB)
        speed_kbs = (total_bytes / 1024.0 / duration_sec) if duration_sec > 0 else 0.0

        knowledge_base["protocols"][protocol_l4] = (knowledge_base["protocols"].get(protocol_l4, 0) + total_bytes)

        flow_record = {
            "id": flow_id,
            "src": f"{src_ip}:{src_port}" if src_port != "" else src_ip,
            "dst": f"{dst_ip}:{dst_port}" if dst_port != "" else dst_ip,
            "proto": protocol_l4,
            "category": categoria,
            "sni": hostname,
            "ja4": ja4,
            "os": os_name,
            "bytes": total_bytes,
            "bytes_sent": bytes_sent,
            "bytes_rcvd": bytes_rcvd,
            "direction": direction,
            "duration": duration_str,
            "duration_sec": duration_sec,
            "speed_kbs": speed_kbs,
            "risks": effective_risks,
            "entropy": entropy_val,
            "tls_version": tls_version,
            "cipher": cipher_suite,
            "alpn": alpn_advertised,
            "app": proto_app
        }

        for r in effective_risks:
            knowledge_base["all_risks"][r] = knowledge_base["all_risks"].get(r, 0) + 1

            # Controllo di coerenza JA4/SNI
            mismatch_anomalies = verifica_mismatch_ja4_sni(flow_record)
            if mismatch_anomalies:
                flow_record["risks"].extend(mismatch_anomalies)
                for anomalia in mismatch_anomalies:
                    knowledge_base["all_risks"][anomalia] = knowledge_base["all_risks"].get(anomalia, 0) + 1

        knowledge_base["flows_list"].append(flow_record)

        if hostname:
            knowledge_base["all_domains"].add(hostname)

        # Mappatura per Host
        if src_ip:
            if src_ip not in knowledge_base["hosts"]:
                knowledge_base["hosts"][src_ip] = {
                    "ja4": set(),  # fingerprint uniche osservate per un determinato host
                    "domains": set(),  # insieme di domini contattati da uno specifico host
                    "protocolli_app": set(),
                    "frequenza_app": {}, # Contatore connessioni per app --> # connessioni/flussi per app per uno specifico host
                    "frequenza_domini": {}, # Contatore connessioni per dominio --> # volte che un determinato dominio viene incontrato nei flussi di rete di uno specifico host
                    "volume_byte_app": {},
                    "categorie": {}, # categoria: quantità traffico in byte
                    "breeds": {}, # breed: quantità in byte
                    "risks": {},
                    "flows_list": [],
                    "os_name": ""
                }

            if ja4:
                knowledge_base["hosts"][src_ip]["ja4"].add(ja4)

            if hostname:
                knowledge_base["hosts"][src_ip]["domains"].add(hostname)
                # Incrementa il contatore del dominio di 1 ogni volta che lo incontra
                knowledge_base["hosts"][src_ip]["frequenza_domini"][hostname] = knowledge_base["hosts"][src_ip]["frequenza_domini"].get(hostname, 0) + 1

            if proto_app != "Unknown":
                # Memorizziamo il protocollo/applicazione ricavato da nDPI
                knowledge_base["hosts"][src_ip]["protocolli_app"].add(proto_app)
                # Incrementa le connessioni
                knowledge_base["hosts"][src_ip]["frequenza_app"][proto_app] = knowledge_base["hosts"][src_ip]["frequenza_app"].get(proto_app, 0) + 1
                # Somma i byte totali dell'applicazione
                knowledge_base["hosts"][src_ip]["volume_byte_app"][proto_app] = knowledge_base["hosts"][src_ip]["volume_byte_app"].get(proto_app, 0) + total_bytes

            if categoria != "Unspecified":
                knowledge_base["hosts"][src_ip]["categorie"][categoria] = knowledge_base["hosts"][src_ip]["categorie"].get(categoria, 0) + total_bytes


            if os_name != "Unknown":
                current_os = knowledge_base["hosts"][src_ip].get("os_name", "")

                if not current_os or current_os == "Unknown":
                    knowledge_base["hosts"][src_ip]["os_name"] = os_name
                # Se ha solo il fingerprint generico (macOS/Linux/Windows) --> sovrascrivo con quello piu specifico
                elif current_os in ["macOS", "Linux", "Windows"] and os_name not in ["macOS", "Linux", "Windows"]:
                    knowledge_base["hosts"][src_ip]["os_name"] = os_name

            if breed != "Unspecified":
                knowledge_base["hosts"][src_ip]["breeds"][breed] = knowledge_base["hosts"][src_ip]["breeds"].get(breed, 0) + total_bytes

            if flow_record:
                knowledge_base["hosts"][src_ip]["flows_list"].append(flow_record)

            for r in effective_risks:
                if r not in knowledge_base["hosts"][src_ip]["risks"]:
                    knowledge_base["hosts"][src_ip]["risks"][r] = []
                knowledge_base["hosts"][src_ip]["risks"][r].append((flow_id, risk_score))

        # Mappatura per Fingerprint JA4
        if ja4:
            if ja4 not in knowledge_base["ja4_to_info"]:
                knowledge_base["ja4_to_info"][ja4] = {"domains": set(), "protocols_app": set(), "hosts": set()}
            if hostname:
                knowledge_base["ja4_to_info"][ja4]["domains"].add(hostname)
            if proto_app != "Unknown":
                knowledge_base["ja4_to_info"][ja4]["protocols_app"].add(proto_app)
            if src_ip:
                knowledge_base["ja4_to_info"][ja4]["hosts"].add(src_ip)

        idx += 3

    return knowledge_base

