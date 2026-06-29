# Analisi del Traffico di Rete con AI e ntopng MCP Server

---

**Studente:** Jacopo Andrea Bianco  
**Email:** j.bianco@studenti.unipi.it  
**Matricola:** 671859  
**Corso:** Gestione di Reti — Università di Pisa

---

## Descrizione del Progetto

Questo progetto estende il **server MCP (Model Context Protocol) di ntopng** con strumenti Lua e **due skill AI** che delegano a un modello linguistico (Claude) l'analisi del traffico di rete:

- **`analizza-top-talker`** — analizza il traffico **in ingresso** verso un indirizzo IP locale o specificato, identificando quali host remoti inviano più dati e valutando se il loro comportamento è anomalo.
- **`rileva-traffico-ai`** — misura quanto del traffico osservato è **usato per sistemi AI**: volume, quota sul totale e numero di connessioni, con la possibilità di concentrarsi su un singolo servizio (es. ChatGPT).

L'idea alla base è delegare a un modello linguistico (Claude) il compito di orchestrare la raccolta e l'interpretazione dei dati di rete: l'LLM interroga il server MCP di ntopng, correla le informazioni su flussi attivi, host e topologia, e produce un report strutturato con un giudizio motivato. Le metriche considerate includono il volume di traffico, il protocollo applicativo, il nome host, l'origine geografica, lo score di rischio ntopng e lo stato blacklist di ciascun host. L'utente non configura soglie né legge raw data — chiede in linguaggio naturale e riceve un'analisi.

ntopng è un sistema di monitoraggio del traffico di rete. Il server MCP espone i dati raccolti come strumenti richiamabili da un LLM, che li combina e interpreta per rispondere a domande come *"chi mi sta mandando traffico?"* con un report visivo e un ragionamento motivato.

---

## Struttura del Repository

```
Progetto_Gestione_di_reti_JAB/
│
├── README.md                          ← questo file
│
├── src/
│   ├── analizza-top-talker-v_finale.md    ← skill Claude: top talker in ingresso
│   ├── rileva-traffico-ai.md              ← skill Claude: traffico usato per sistemi AI
│   └── ntopng_lua_files_mcp/
│       ├── discover_lan.lua               ← tool MCP: scansione LAN attiva
│       └── get_interface_addresses.lua    ← tool MCP: IP dell'interfaccia locale
│
└── experiments/
    ├── network_stress.py                  ← script: download HTTP pesante
    ├── scapy_flood.py                     ← script: pacchetti UDP forgiati con Scapy
    └── results/
        ├── general_traffic/               ← esperimenti skill top talker
        │   ├── results_implicit_host.png       ← baseline, IP rilevato automaticamente
        │   ├── results_with_graph.png          ← stessa analisi con grafico ("con grafico")
        │   ├── results_explicit_host.png       ← analisi con IP target specificato
        │   ├── results_network_stress.png      ← analisi durante download pesante
        │   ├── results_scapy_flood.png         ← analisi durante flood UDP con Scapy
        │   └── Macro/
        │       ├── selection_implicit_host.png    ← selezione IP da lista interfacce
        │       ├── workflow_1:2.png               ← raccolta flussi attivi (Stadio 2)
        │       └── workflow_2:2.png               ← arricchimento host + discover_lan (Stadi 3–4)
        └── AI_traffic/                     ← esperimenti skill traffico AI
            ├── all_AI_Providers.png            ← domanda generica (tutti i provider AI)
            └── specific_AI_Provider.png        ← domanda su un servizio specifico
```

---

## File del Progetto

### `src/ntopng_lua_files_mcp/discover_lan.lua`
Tool MCP che esegue una scansione attiva della LAN e restituisce la lista di tutti i dispositivi visibili con MAC address, IP, hostname, produttore e tipo di dispositivo. Include un fallback sulla tabella MAC passiva di ntopng se la scansione attiva non produce risultati.

### `src/ntopng_lua_files_mcp/get_interface_addresses.lua`
Tool MCP che restituisce tutti gli indirizzi IP assegnati all'interfaccia monitorata da ntopng.

### `src/analizza-top-talker-v_finale.md`
Skill Claude che orchestra l'intera pipeline di analisi del traffico in ingresso. Definisce la logica in 5 stadi: identificazione IP locale → raccolta flussi → arricchimento host → topologia LAN → ragionamento AI e report.

### `src/rileva-traffico-ai.md`
Skill Claude che misura quanto del traffico osservato è usato per sistemi AI. Orchestra i tool MCP per raccogliere i flussi attivi, arricchire ogni server esterno con il nome host e le statistiche, e classificare i server che appartengono a provider AI, producendo volume, quota sul totale e numero di connessioni per provider. Risponde sia alla domanda generale (*"quanto traffico viene usato per sistemi AI?"*) sia a quella su un servizio specifico (*"quanto traffico viene usato per ChatGPT?"*).

### `experiments/network_stress.py`
Script Python che simula un download HTTP pesante da un server esterno pubblico. Usato per generare traffico in ingresso osservabile da ntopng e verificare che la skill lo identifichi correttamente come top sender. La durata di default è 120 secondi.

```bash
python3 experiments/network_stress.py
python3 experiments/network_stress.py --durata <SECONDI>
```

### `experiments/scapy_flood.py`
Script Python che genera pacchetti UDP con IP sorgente forgiato (spoofed) e porta destinazione 80 in flooding usando la libreria Scapy. La porta di destinazione è modificabile direttamente nel sorgente alla riga 21 (`PORTA_DST = 80`). Usato per simulare un host anomalo esterno e verificare che la skill lo classifichi correttamente. La durata di default è 120 secondi.

```bash
sudo python3 experiments/scapy_flood.py --destinazione <IP_DESTINAZIONE> --sorgente <IP_SORGENTE>
sudo python3 experiments/scapy_flood.py --destinazione <IP_DESTINAZIONE> --sorgente <IP_SORGENTE> --durata <SECONDI>
```

> **Richiede:** `pip install scapy` e privilegi `sudo`.

---

## Prerequisiti e Installazione

### 1. ntopng

Scarica e installa ntopng dal repository ufficiale:

```
https://github.com/ntop/ntopng
```

### 2. Claude Code

Scarica il client Claude dal sito ufficiale di Anthropic:

```
https://claude.com/download
```

> **⚠️ Raccomandazione:** si consiglia di usare Claude con un abbonamento a Claude che garantisca accesso ai modelli più capaci. In alternativa, è possibile configurare un LLM locale seguendo questa guida:  
> https://medium.com/@areejzaheer96/claude-code-with-qwen-models-for-free-09679f1d3fff  
> Tuttavia, i modelli locali potrebbero non raggiungere la qualità di ragionamento necessaria per l'analisi del traffico.

### 3. Server MCP di ntopng

Segui la guida ufficiale per configurare il server MCP e collegarlo a Claude Code:

```
https://www.ntop.org/ai-powered-network-monitoring-introducing-ntopng-mcp-server/
```

### 4. Geolocalizzazione (opzionale ma consigliata)

Per arricchire l'analisi con informazioni geografiche sugli host remoti (paese, ASN), configura i database MaxMind GeoLite2 seguendo la guida:

```
https://github.com/ntop/ntopng/blob/dev/doc/README.geolocation.md
```

### 5. File Lua — Tool MCP

I file in `src/ntopng_lua_files_mcp/` sono già stati caricati nel server MCP di ntopng in esecuzione (`scripts/lua/modules/llm/tools/`). Sono inclusi nel repository come riferimento. Per replicare l'ambiente su un'altra macchina, copiarli nella stessa directory e riavviare ntopng.

### 6. Preferenza ntopng: nomi host da TLS/QUIC

La skill `rileva-traffico-ai` riconosce i servizi tramite il **nome host** dei server, ricavato dall'SNI delle connessioni TLS/QUIC. Per far popolare questo campo a ntopng, abilita la relativa preferenza impostando la chiave Redis e riavviando ntopng:

```bash
redis-cli set ntopng.prefs.tls_quic_hostnaming 1
```

Dopo il riavvio, ntopng associa a ogni host il nome del servizio (es. `claude.ai`, `chatgpt.com`), reso disponibile tramite il tool MCP `get_host_info`.

### 7. Installazione delle Skill

Le skill sono file Markdown che Claude Code carica come comandi personalizzati. Per installarle, copiale nella directory dei comandi di Claude:

```bash
cp src/analizza-top-talker-v_finale.md ~/.claude/commands/
cp src/rileva-traffico-ai.md ~/.claude/commands/
```

Saranno disponibili come comandi `/analizza-top-talker-v_finale` e `/rileva-traffico-ai`, oppure invocabili direttamente in linguaggio naturale — Claude le riconosce automaticamente:

- **`analizza-top-talker`**: *"chi mi sta mandando traffico?"*, *"chi fa più traffico verso 192.168.1.45?"*, *"c'è un host sospetto che sta mandando tanto traffico?"*
- **`rileva-traffico-ai`**: *"quanto traffico viene usato per sistemi AI?"*, *"quanto traffico viene usato per ChatGPT?"*

> **Nota (`analizza-top-talker`):** aggiungendo *"con grafico"* o *"con visualizzazione"* alla richiesta viene generato un widget interattivo con la distribuzione del traffico. Il tempo di elaborazione in questo caso può essere superiore rispetto all'analisi standard.

---

## Esperimenti — Skill `analizza-top-talker`

Sono stati condotti 5 esperimenti per verificare il corretto funzionamento della pipeline in scenari diversi.

La cartella `results/general_traffic/Macro/` contiene screenshot del funzionamento interno della pipeline: `selection_implicit_host.png` mostra il momento in cui la skill presenta all'utente la lista degli indirizzi IP trovati e chiede quale usare; `workflow_1:2.png` mostra la raccolta dei flussi attivi (Stadio 2) con i dati CSV grezzi restituiti dal server MCP; `workflow_2:2.png` mostra le chiamate parallele a `get_host_info` per ogni host remoto e il risultato di `discover_lan`.

---

### Esperimento 1 — Analisi baseline, IP rilevato automaticamente

**Richiesta:** *"chi mi sta mandando traffico?"*

La skill non riceve un IP nella richiesta, chiama `get_interface_addresses` e presenta all'utente la lista degli indirizzi trovati sull'interfaccia (IPv4 + IPv6), chiedendo quale usare. Selezionato `192.168.1.45`, la pipeline completa viene eseguita.

**Risultato:** il traffico in ingresso è dominato da servizi Apple (iCloud, AppStore) e CDN standard. Tutti gli host ricevono giudizio **normale** — nessuna anomalia rilevata. La topologia LAN mostra i dispositivi attivi sulla rete, con `camera-4.station` tra quelli in comunicazione con la macchina locale.

**Screenshot:** `results/general_traffic/results_implicit_host.png` · `results/general_traffic/Macro/selection_implicit_host.png`

---

### Esperimento 2 — Analisi baseline con grafico

**Richiesta:** *"chi mi sta mandando traffico? fai anche il grafico"*

Stessa analisi dell'esperimento 1, con l'aggiunta del widget grafico (attivato dalla parola chiave *"con grafico"*). Il report include un grafico a barre interattivo che mostra la distribuzione di `bytes_in` tra i 10 host rilevati, rendendo visivamente immediata la dominanza dei servizi Apple/iCloud rispetto agli altri mittenti.

**Risultato:** identico al baseline — traffico normale. Il grafico evidenzia chiaramente il peso relativo di ciascun mittente e facilita l'identificazione visiva di eventuali outlier.

**Screenshot:** `results/general_traffic/results_with_graph.png`

---

### Esperimento 3 — Analisi con IP target specificato

**Richiesta:** *"chi sta mandando traffico verso 160.79.104.10?"*

L'IP viene passato direttamente nella richiesta: la skill lo usa senza chiedere conferma e procede direttamente alla raccolta flussi verso quell'indirizzo.

**Risultato:** viene rilevato 1 solo mittente attivo — `192.168.1.45` (la macchina locale stessa, Macmini) con **1.59 MB**, **100%** della quota, su 63 flussi TLS/QUIC. Score ntopng: **406**, giudizio **da monitorare**. Lo score elevato viene correttamente segnalato come elemento da tenere sotto controllo, indipendentemente dal volume.

**Screenshot:** `results/general_traffic/results_explicit_host.png`

---

### Esperimento 4 — Download HTTP pesante (`network_stress.py`)

**Procedura:** avviare il download in background, poi invocare la skill.

```bash
python3 experiments/network_stress.py
```

**Richiesta:** *"chi mi sta mandando traffico?"*

**Risultato:** `speedtest.tele2.net` (`90.130.70.73`, Svezia) appare al primo posto con **151.7 MB** ricevuti in circa 22 secondi — pari al **99.3%** di tutto il traffico in ingresso. Protocollo HTTP, score 0, giudizio **normale**: il volume enorme è assolutamente coerente con un test di velocità avviato intenzionalmente. Il residuo 0.7% è traffico TLS/QUIC ordinario verso Apple, Microsoft e GitHub. La skill distingue correttamente traffico volumetricamente dominante ma contestualmente lecito.

**Screenshot:** `results/general_traffic/results_network_stress.png`

---

### Esperimento 5 — Flood UDP con Scapy (`scapy_flood.py`)

**Procedura:** avviare il flood con un IP sorgente simulato, poi invocare la skill.

```bash
sudo python3 experiments/scapy_flood.py --destinazione 192.168.1.45 --sorgente 200.34.1.2
```

**Richiesta:** *"c'è un host sospetto che sta mandando tanto traffico?"*

**Risultato:** `200.34.1.2` (Messico) domina la classifica al **primo posto** con **121.5 MB** ricevuti — pari al **99.7%** di tutto il traffico in ingresso. Protocollo: `Protobuf/UDP` sulla porta 80. Score ntopng: 0 (IP non ancora in blacklist), ma giudizio: **critico**. La skill segnala tre anomalie concorrenti: la porta 80 è convenzionalmente TCP/HTTP e non UDP; Protobuf su UDP non ha alcuna relazione con un web server; `bytes_srv2cli = 0` indica che la macchina locale non ha risposto a nessun pacchetto. Il pattern è coerente con un UDP flood o un'amplification attack. Nonostante lo score nullo, la combinazione di fattori porta la skill ad assegnare il giudizio più grave, con raccomandazione immediata di bloccare l'IP sul firewall.

**Screenshot:** `results/general_traffic/results_scapy_flood.png`

---

## Esperimenti — Skill `rileva-traffico-ai`

Per generare traffico verso sistemi AI è sufficiente porre qualche domanda ai modelli durante il monitoraggio: bastano poche interazioni nel browser o nei rispettivi client per produrre flussi osservabili da ntopng. In questi test sono stati usati **Claude**, **ChatGPT** e **Copilot**.

---

### Esperimento 6 — Domanda generica (tutti i provider AI)

**Richiesta:** *"quanto traffico viene usato per sistemi AI?"*

La skill raccoglie tutti i flussi attivi, arricchisce ogni server esterno con nome host e statistiche, e classifica quelli appartenenti a provider AI. Il report mostra il volume totale diretto all'AI, la quota sul traffico complessivo e il numero di connessioni, con la ripartizione per provider (Claude, ChatGPT, Copilot).

**Screenshot:** `results/AI_traffic/all_AI_Providers.png`

---

### Esperimento 7 — Domanda su un servizio specifico

**Richiesta:** *"quanto traffico viene usato per ChatGPT?"*

La skill restringe l'analisi al solo servizio indicato: considera AI unicamente i server di quel provider e aggrega tutto il resto nel Resto. Il report quantifica volume, quota sul totale e numero di connessioni del singolo servizio richiesto.

**Screenshot:** `results/AI_traffic/specific_AI_Provider.png`
