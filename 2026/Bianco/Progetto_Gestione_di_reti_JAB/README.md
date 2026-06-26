# Analisi del Traffico in Ingresso con AI e ntopng MCP Server

---

**Studente:** Jacopo Andrea Bianco  
**Email:** j.bianco@studenti.unipi.it  
**Matricola:** 671859  
**Corso:** Gestione di Reti — Università di Pisa

---

## Descrizione del Progetto

Questo progetto estende il **server MCP (Model Context Protocol) di ntopng** con nuovi strumenti Lua e una skill AI per analizzare il traffico in ingresso verso un indirizzo IP locale o specificato, identificando quali host remoti inviano più dati e valutando se il loro comportamento è anomalo.

L'idea alla base è delegare a un modello linguistico (Claude) il compito di orchestrare la raccolta e l'interpretazione dei dati di rete: l'LLM interroga il server MCP di ntopng, correla le informazioni su flussi attivi, host e topologia LAN, e produce un report strutturato con un giudizio motivato per ogni mittente rilevante. Le metriche considerate includono il volume di traffico ricevuto, il protocollo applicativo, l'origine geografica, lo score di rischio ntopng e lo stato blacklist di ciascun host. L'utente non configura soglie né legge raw data — chiede in linguaggio naturale e riceve un'analisi.

ntopng è un sistema di monitoraggio del traffico di rete. Il server MCP espone i dati raccolti come strumenti richiamabili da un LLM, che li combina e interpreta per rispondere a domande come *"chi mi sta mandando traffico?"* con un report visivo e un ragionamento motivato.

---

## Struttura del Repository

```
Progetto_Gestione_di_reti_JAB/
│
├── README.md                          ← questo file
│
├── src/
│   ├── analizza-top-talker-v_finale.md    ← skill Claude per l'analisi
│   └── ntopng_lua_files_mcp/
│       ├── discover_lan.lua               ← tool MCP: scansione LAN attiva
│       └── get_interface_addresses.lua    ← tool MCP: IP dell'interfaccia locale
│
└── experiments/
    ├── network_stress.py                  ← script: download HTTP pesante
    ├── scapy_flood.py                     ← script: pacchetti UDP forgiati con Scapy
    └── results/
        ├── results_implicit_host.png       ← analisi baseline, IP rilevato automaticamente
        ├── results_with_graph.png         ← stessa analisi con grafico ("con grafico")
        ├── results_explicit_host.png      ← analisi con IP target specificato nella richiesta
        ├── results_network_stress.png     ← analisi durante download pesante
        ├── results_scapy_flood.png        ← analisi durante flood UDP con Scapy
        └── Macro/
            ├── selection_implicit_host.png    ← selezione IP da lista interfacce
            ├── workflow_1:2.png               ← raccolta flussi attivi (Stadio 2)
            └── workflow_2:2.png               ← arricchimento host + discover_lan (Stadi 3–4)
```

---

## File del Progetto

### `src/ntopng_lua_files_mcp/discover_lan.lua`
Tool MCP che esegue una scansione attiva della LAN e restituisce la lista di tutti i dispositivi visibili con MAC address, IP, hostname, produttore e tipo di dispositivo. Include un fallback sulla tabella MAC passiva di ntopng se la scansione attiva non produce risultati.

### `src/ntopng_lua_files_mcp/get_interface_addresses.lua`
Tool MCP che restituisce tutti gli indirizzi IP assegnati all'interfaccia monitorata da ntopng.

### `src/analizza-top-talker-v_finale.md`
Skill Claude che orchestra l'intera pipeline di analisi. Definisce la logica in 5 stadi: identificazione IP locale → raccolta flussi → arricchimento host → topologia LAN → ragionamento AI e report. Vedi la sezione [Installazione della Skill](#installazione-della-skill) per come attivarla.

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

### 6. Installazione della Skill

La skill è un file Markdown che Claude Code carica come comando personalizzato. Per installarla:

1. Copia il file nella directory dei comandi di Claude:

```bash
cp src/analizza-top-talker-v_finale.md ~/.claude/commands/
```

2. La skill sarà disponibile in Claude Code come comando `/analizza-top-talker-v_finale`

3. Oppure si può invocarla in linguaggio naturale — Claude la riconosce automaticamente quando l'utente chiede, ad esempio: *"chi mi sta mandando traffico?"*, *"chi fa più traffico verso 192.168.1.45?"*, *"c'è un host sospetto che sta mandando tanto traffico?"*

> **Nota:** aggiungendo *"con grafico"* o *"con visualizzazione"* alla richiesta viene generato un widget interattivo con la distribuzione del traffico. Il tempo di elaborazione in questo caso può essere superiore rispetto all'analisi standard.

---

## Esperimenti

Sono stati condotti 5 esperimenti per verificare il corretto funzionamento della pipeline in scenari diversi.

La cartella `results/Macro/` contiene screenshot del funzionamento interno della pipeline: `selection_implicit_host.png` mostra il momento in cui la skill presenta all'utente la lista degli indirizzi IP trovati e chiede quale usare; `workflow_1:2.png` mostra la raccolta dei flussi attivi (Stadio 2) con i dati CSV grezzi restituiti dal server MCP; `workflow_2:2.png` mostra le chiamate parallele a `get_host_info` per ogni host remoto e il risultato di `discover_lan`.

---

### Esperimento 1 — Analisi baseline, IP rilevato automaticamente

**Richiesta:** *"chi mi sta mandando traffico?"*

La skill non riceve un IP nella richiesta, chiama `get_interface_addresses` e presenta all'utente la lista degli indirizzi trovati sull'interfaccia (IPv4 + IPv6), chiedendo quale usare. Selezionato `192.168.1.45`, la pipeline completa viene eseguita.

**Risultato:** il traffico in ingresso è dominato da servizi Apple (iCloud, AppStore) e CDN standard. Tutti gli host ricevono giudizio **normale** — nessuna anomalia rilevata. La topologia LAN mostra i dispositivi attivi sulla rete, con `camera-4.station` tra quelli in comunicazione con la macchina locale.

**Screenshot:** `results/results_implicit_host.png` · `results/Macro/selection_implicit_host.png`

---

### Esperimento 2 — Analisi baseline con grafico

**Richiesta:** *"chi mi sta mandando traffico? fai anche il grafico"*

Stessa analisi dell'esperimento 1, con l'aggiunta del widget grafico (attivato dalla parola chiave *"con grafico"*). Il report include un grafico a barre interattivo che mostra la distribuzione di `bytes_in` tra i 10 host rilevati, rendendo visivamente immediata la dominanza dei servizi Apple/iCloud rispetto agli altri mittenti.

**Risultato:** identico al baseline — traffico normale. Il grafico evidenzia chiaramente il peso relativo di ciascun mittente e facilita l'identificazione visiva di eventuali outlier.

**Screenshot:** `results/results_with_graph.png`

---

### Esperimento 3 — Analisi con IP target specificato

**Richiesta:** *"chi sta mandando traffico verso 160.79.104.10?"*

L'IP viene passato direttamente nella richiesta: la skill lo usa senza chiedere conferma e procede direttamente alla raccolta flussi verso quell'indirizzo.

**Risultato:** viene rilevato 1 solo mittente attivo — `192.168.1.45` (la macchina locale stessa, Macmini) con **1.59 MB**, **100%** della quota, su 63 flussi TLS/QUIC. Score ntopng: **406**, giudizio **da monitorare**. Lo score elevato viene correttamente segnalato come elemento da tenere sotto controllo, indipendentemente dal volume.

**Screenshot:** `results/results_explicit_host.png`

---

### Esperimento 4 — Download HTTP pesante (`network_stress.py`)

**Procedura:** avviare il download in background, poi invocare la skill.

```bash
python3 experiments/network_stress.py
```

**Richiesta:** *"chi mi sta mandando traffico?"*

**Risultato:** `speedtest.tele2.net` (`90.130.70.73`, Svezia) appare al primo posto con **151.7 MB** ricevuti in circa 22 secondi — pari al **99.3%** di tutto il traffico in ingresso. Protocollo HTTP, score 0, giudizio **normale**: il volume enorme è assolutamente coerente con un test di velocità avviato intenzionalmente. Il residuo 0.7% è traffico TLS/QUIC ordinario verso Apple, Microsoft e GitHub. La skill distingue correttamente traffico volumetricamente dominante ma contestualmente lecito.

**Screenshot:** `results/results_network_stress.png`

---

### Esperimento 5 — Flood UDP con Scapy (`scapy_flood.py`)

**Procedura:** avviare il flood con un IP sorgente simulato, poi invocare la skill.

```bash
sudo python3 experiments/scapy_flood.py --destinazione 192.168.1.45 --sorgente 200.34.1.2
```

**Richiesta:** *"c'è un host sospetto che sta mandando tanto traffico?"*

**Risultato:** `200.34.1.2` (Messico) domina la classifica al **primo posto** con **121.5 MB** ricevuti — pari al **99.7%** di tutto il traffico in ingresso. Protocollo: `Protobuf/UDP` sulla porta 80. Score ntopng: 0 (IP non ancora in blacklist), ma giudizio: **critico**. La skill segnala tre anomalie concorrenti: la porta 80 è convenzionalmente TCP/HTTP e non UDP; Protobuf su UDP non ha alcuna relazione con un web server; `bytes_srv2cli = 0` indica che la macchina locale non ha risposto a nessun pacchetto. Il pattern è coerente con un UDP flood o un'amplification attack. Nonostante lo score nullo, la combinazione di fattori porta la skill ad assegnare il giudizio più grave, con raccomandazione immediata di bloccare l'IP sul firewall.

**Screenshot:** `results/results_scapy_flood.png`
