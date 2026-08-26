#!/usr/bin/env python3

import re
import os
import shutil
import sys
import subprocess

import json
import urllib.request


def run_ndpi_reader(pcap_path: str, output_txt_path: str, ndpi_bin: str = "ndpiReader") -> None:
    """
    Esegue ndpiReader a riga di comando sul file pcapng e salva l'output su file .txt.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"File PCAP non trovato: '{pcap_path}'")

    # Verifica se l'eseguibile ndpiReader esiste o è nel PATH
    bin_path = shutil.which(ndpi_bin)
    if not bin_path:
        # Controlla percorsi relativi comuni
        common_paths = [
            "./nDPI/example/ndpiReader",
            "../nDPI/example/ndpiReader",
            os.path.expanduser("~/nDPI/example/ndpiReader"),
            ndpi_bin
        ]
        for p in common_paths:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                bin_path = p
                break

    if not bin_path:
        raise FileNotFoundError(
            f"Eseguibile '{ndpi_bin}' non trovato. Compilalo dentro nDPI/example/ o specificalo esplicitamente."
        )

    cmd = [bin_path, "-i", pcap_path, "-v", "2"]

    with open(output_txt_path, "w", encoding="utf-8") as out_file:
        result = subprocess.run(cmd, stdout=out_file, stderr=subprocess.PIPE, text=True, errors="ignore")

    if result.returncode != 0 and result.stderr:
        # Se ndpiReader restituisce errori critici
        raise RuntimeError(f"Errore durante l'esecuzione di ndpiReader:\n{result.stderr}")

def query_local_ai(prompt: str, kb_data: dict) -> str:
    url = "http://localhost:1234/v1/chat/completions"
    
    # Comprimo il JSON togliendo spazi e a capo (Risparmiamo tantissimi token!)
    kb_compact = json.dumps(kb_data, separators=(',', ':'), default=list)

    # Preparo un contesto dicendo all'AI chi è e che dati ha a disposizione
    system_context = f"""Sei un analista di rete e cybersecurity. 
                        Rispondi alle domande in modo conciso e preciso basandoti SOLO su questi dati nDPI: {kb_compact}"""

    # Corpo della richiesta HTTP che verrà mandata al modello AI locale
    # Formato standard compatibile con Bionic/LM Studio
    # Aggiunto il campo "model" (richiesto dallo standard OpenAI)
    payload = {
        "model": "local-model", 
        "messages": [
            {"role": "system", "content": system_context},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2 # Controlla quanto il modello deve essere variabile/creativo nella generazione della risposta
    }

    # richiesta effettiva per il modello
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req) as response: #invio la richiesta HTTP al server locale, ed attendo la risposta
            result = json.loads(response.read().decode('utf-8'))
            return result["choices"][0]["message"]["content"] # prendo il testo { choices : [ { message: { role: ... , content: ... }}, ... ] }
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode('utf-8')
        return f"[-] Errore HTTP {e.code}: {error_msg}"
    except Exception as e:
        return f"[-] Errore di connessione a Bionic: {e}"


def parse_ndpi_output(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Errore: File '{file_path}' non trovato!")
        print("    Assicurati di aver generato il file con il comando:")
        print("    ./example/ndpiReader -i ~/Scrivania/traffico_telefono.pcapng -v 2 > ~/Scrivania/ndpi_output.txt")
        print("    Oppure direttamente nella sezione di conversione PCAP/PCAPNG --> TXT con nDPI nel pannello laterale del Tool")
        sys.exit(1)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Separo i singoli blocchi di flusso --> guardo le linee che inziano con un numero seguito da TCP || UDP || ICMP
    flow_blocks = re.split(r'\n\s*\d+\t(?:TCP|UDP|ICMP)', content)

    # Uso i set() per mantenere gli elenchi senza duplicati (es. domini unici),
    # e i dizionari per memorizzare i contatori di frequenza.
    knowledge_base = {
        "hosts": {},
        # ip -> { ja4: set(), domains: set(), protocolli_di_rete: set(), frequenza_app: dict(), frequenza_domini: dict(), volume_byte_app: dict() }
        "ja4_to_info": {},  # ja4 -> { domains: set(), L5_protocols: set(), hosts: set() }
        "all_domains": set()  # insieme di tutti i domini unici osservati
    }

    for block in flow_blocks[1:]:
        # Estrazione Host Sorgente (IP:Porta)
        src_match = re.search(r'([0-9a-fA-F:\.]+):(\d+)\s*(?:<->|->)', block)
        src_ip = src_match.group(1) if src_match else None

        # Estrazione Protocollo L5 riconosciuto da nDPI
        proto_match = re.search(r'\[proto:\s*[^/]+/([^\]]+)\]', block)
        protocol = proto_match.group(1) if proto_match else "Unknown"

        # Estrazione Categoria nDPI (es. Network, SocialNetwork, Web, ecc.)
        cat_match = re.search(r'\[cat:\s*([^/]+)/\d+\]', block)
        categoria = cat_match.group(1) if cat_match else "Unspecified"

        # Estrazione Dominio / SNI
        sni_match = re.search(r'\[Hostname/SNI:\s*([^\]]+)\]', block)
        hostname = sni_match.group(1) if sni_match else None

        # Estrazione JA4
        ja4_match = re.search(r'\[JA4:\s*([^\]]+)\]', block)
        ja4 = ja4_match.group(1) if ja4_match else None

        # Estrazione Volume Dati (Byte)
        byte_match = re.search(r'\[\d+\s+pkts/(\d+)\s+bytes\s+(?:<->|->)\s+\d+\s+pkts/(\d+)\s+bytes\]', block)
        if byte_match:
            bytes_sent = int(byte_match.group(1))
            bytes_rcvd = int(byte_match.group(2))
            total_bytes = bytes_sent + bytes_rcvd
        else:
            total_bytes = 0

        if hostname:
            knowledge_base["all_domains"].add(hostname)

        # Mappatura per Host
        if src_ip:
            if src_ip not in knowledge_base["hosts"]:
                knowledge_base["hosts"][src_ip] = {
                    "ja4": set(),  # fingerprint uniche osservate per un determinato host
                    "domains": set(),  # insieme di domini contattati da uno specifico host
                    "protocolli_di_rete": set(),  # Contenitore solo per protocolli
                    "frequenza_app": {},
                    # Contatore connessioni per app --> # connessioni/flussi per app per uno specifico host
                    "frequenza_domini": {},
                    # Contatore connessioni per dominio --> # volte che un determinato dominio viene incontrato nei flussi di rete di uno specifico host
                    "volume_byte_app": {}
                }

            if ja4:
                knowledge_base["hosts"][src_ip]["ja4"].add(ja4)

            if hostname:
                knowledge_base["hosts"][src_ip]["domains"].add(hostname)
                # Incrementa il contatore del dominio di 1 ogni volta che lo incontra
                knowledge_base["hosts"][src_ip]["frequenza_domini"][hostname] = knowledge_base["hosts"][src_ip]["frequenza_domini"].get(hostname, 0) + 1
            if protocol != "Unknown":
                # Se è un protocollo di livello 3/4 lo mettiamo nei protocolli di rete
                if categoria == "Network":
                    knowledge_base["hosts"][src_ip]["protocolli_di_rete"].add(protocol)
                # Altrimenti è una vera e propria applicazione L5/L7 (es. QUIC.Instagram)
                else:
                    # Incrementa le connessioni
                    knowledge_base["hosts"][src_ip]["frequenza_app"][protocol] = knowledge_base["hosts"][src_ip]["frequenza_app"].get(protocol, 0) + 1
                    # Somma i byte totali dell'applicazione
                    knowledge_base["hosts"][src_ip]["volume_byte_app"][protocol] = knowledge_base["hosts"][src_ip]["volume_byte_app"].get(protocol, 0) + total_bytes

        # Mappatura per Fingerprint JA4
        if ja4:
            if ja4 not in knowledge_base["ja4_to_info"]:
                knowledge_base["ja4_to_info"][ja4] = {"domains": set(), "protocols": set(), "hosts": set()}
            if hostname:
                knowledge_base["ja4_to_info"][ja4]["domains"].add(hostname)
            if protocol != "Unknown":
                knowledge_base["ja4_to_info"][ja4]["protocols"].add(protocol)
            if src_ip:
                knowledge_base["ja4_to_info"][ja4]["hosts"].add(src_ip)

    return knowledge_base

