#!/usr/bin/env python3

import re
import os
import sys

import json
import urllib.request

def query_local_ai(prompt: str, kb_data: dict) -> str:
    url = "http://localhost:1234/v1/chat/completions"
    
    # Comprimiamo il JSON togliendo spazi e a capo (Risparmiamo tantissimi token!)
    kb_compact = json.dumps(kb_data, separators=(',', ':'), default=list)

    # Prepariamo un contesto dicendo all'AI chi è e che dati ha a disposizione
    system_context = f"""Sei un analista di rete e cybersecurity. 
                        Rispondi alle domande in modo conciso e preciso basandoti SOLO su questi dati nDPI: {kb_compact}"""

    # Corpo della richiesta HTTP che verrà mandata al modello AI locale
    # Formato standard compatibile con Bionic/LM Studio
    # Aggiungiamo il campo "model" (richiesto dallo standard OpenAI)
    payload = {
        "model": "local-model", 
        "messages": [
            {"role": "system", "content": system_context},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2 # Controlla quanto il modello deve essere variabile/creativo nella generazione della risposta
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result["choices"][0]["message"]["content"]
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
        sys.exit(1)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Separo i singoli blocchi di flusso --> guardo le linee che inziano con un numero seguito da TCP || UDP || ICMP
    flow_blocks = re.split(r'\n\s*\d+\t(?:TCP|UDP|ICMP)', content)

    # Uso i set() per mantenere gli elenchi senza duplicati (es. domini unici),
    # e i dizionari per memorizzare i contatori di frequenza.
    knowledge_base = {
        "hosts": {},  # ip -> { ja4: set(), domains: set(), protocolli_di_rete: set(), frequenza_app: dict(), frequenza_domini: dict(), volume_byte_app: dict() }
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
                    "ja4": set(), # fingerprint uniche osservate per un determinato host
                    "domains": set(), # insieme di domini contattati da uno specifico host
                    "protocolli_di_rete": set(), # Contenitore solo per protocolli
                    "frequenza_app": {},      # Contatore connessioni per app --> # connessioni/flussi per app per uno specifico host
                    "frequenza_domini": {},   # Contatore connessioni per dominio --> # volte che un determinato dominio viene incontrato nei flussi di rete di uno specifico host
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


def main(path):
    #path = "/home/andrea/Scrivania/ndpi_output.txt"
    kb = parse_ndpi_output(path)

    print("=" * 65)
    print("       GESTIONE RETI: BASELINE & JA4 ANALYZER       ")
    print("=" * 65)
    print(
        f"[*] Dati caricati: {len(kb['hosts'])} host, {len(kb['ja4_to_info'])} JA4, {len(kb['all_domains'])} domini.\n")

    while True:
        print("\n" + "-" * 40)
        print(" MENU OPERAZIONI:")
        print("  1. Quali fingerprint JA4 usa l'host X?")
        print("  2. Quali domini/app sono associati alla fingerprint JA4 Y?")
        print("  3. Mostra riassunto completo della baseline")
        print("  4. Interroga l'Intelligenza Artificiale locale")
        print("  5. Esci")
        print("-" * 40)

        scelta = input("Scegli un'opzione (1-5): ").strip()

        if scelta == "1":
            ip = input("\nInserisci l'indirizzo IP (es. 192.168.2.2): ").strip()
            host_info = kb["hosts"].get(ip)
            if host_info and host_info["ja4"]:
                print(f"\n[+] L'host {ip} usa le seguenti {len(host_info['ja4'])} fingerprint JA4:")
                for fp in sorted(host_info["ja4"]):
                    print(f"  • {fp}")
            else:
                print(f"\n[-] Nessuna fingerprint JA4 trovata per l'host '{ip}'.")

        elif scelta == "2":
            fp = input("\nInserisci la stringa JA4: ").strip()
            trovato = False
            for full_ja4, data in kb["ja4_to_info"].items():
                if fp.lower() in full_ja4.lower():
                    trovato = True
                    protos = ', '.join(data['protocols']) if data['protocols'] else 'Generico TLS'
                    print(f"\n[+] Risultati per JA4: {full_ja4}")
                    print(f"  • Applicazioni rilevate: {protos}")
                    print(f"  • Host sorgente: {', '.join(data['hosts'])}")
                    print(f"  • Domini contattati ({len(data['domains'])}):")
                    for d in sorted(data["domains"]):
                        print(f"      - {d}")
            if not trovato:
                print(f"\n[-] Fingerprint '{fp}' non trovata nella baseline.")

        elif scelta == "3":
            print("\n" + "=" * 60)
            print("       PANORAMICA DELLA BASELINE DEL TRAFFICO")
            print("=" * 60)
            print(f"  • Host rilevati:          {len(kb['hosts'])}")
            print(f"  • Fingerprint JA4 uniche: {len(kb['ja4_to_info'])}")
            print(f"  • Domini totali osservati:{len(kb['all_domains'])}\n")

            print("DETTAGLIO APP <-> JA4 <-> DOMINI:")
            for ja4, data in sorted(kb["ja4_to_info"].items()):
                protos = ', '.join(data['protocols']) if data['protocols'] else 'TLS/QUIC generico' # creo una lista di protocolli sepatata da ','
                print(f"\n[{protos}] -> {ja4}")
                print(f"  Host che la usano: {', '.join(data['hosts'])}")
                print(f"  Domini associati ({len(data['domains'])}):")
                if data['domains']:
                    for d in sorted(data['domains']):
                        print(f"    - {d}")
                else:
                    print("    - (Nessun dominio SNI in chiaro catturato)")

        elif scelta == "4":
            domanda = input("\nCosa vuoi sapere dal traffico analizzato? ")
            print("\n[L'AI sta leggendo la baseline...]")

            # I set() di Python non sono supportati nel formato JSON, li convertiamo in liste
            def set_to_list(obj):
                if isinstance(obj, set): return list(obj)
                if isinstance(obj, dict): return {k: set_to_list(v) for k, v in obj.items()}
                return obj

            kb_clean = set_to_list(kb)
            risposta = query_local_ai(domanda, kb_clean)
            print(f"\n[AI]:\n{risposta}")

        elif scelta == "5":
            print("\nChiusura programma.")
            break
        else:
            print("\n[-] Opzione non valida. Inserisci un numero da 1 a 5.")


if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Il programma si aspetta in input il path del file .txt di output di ndpi e solo quello...")
        sys.exit(1)
    main(sys.argv[1])