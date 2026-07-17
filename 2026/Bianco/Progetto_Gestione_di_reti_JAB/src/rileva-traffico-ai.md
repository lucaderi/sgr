Usa questa skill quando l'utente chiede: quanto traffico viene usato per sistemi AI? Oppure la stessa domanda con un servizio specifico: quanto traffico viene usato per <servizio>? Misura quanto del traffico osservato è diretto a provider di AI/LLM: volume, quota sul totale e numero di connessioni.

## Pipeline

1. Chiama `get_live_flows_summary` con `group_by=destination`. Il campo `total_bytes` nell'header è il **traffico totale** — il denominatore di ogni quota. Per ogni `srv_ip` estrai `bytes`, `num_flows`, `packets`.

2. Scarta gli IP che non sono server esterni: privati, multicast, broadcast.

3. Chiama `get_live_flows_for_host` su **tutti** i `srv_ip` rimasti, in parallelo e in una sola tornata. Per ogni `srv_ip` estrai `l4_proto`, `app_proto`.

4. Chiama `get_host_info` su **tutti** i `srv_ip` rimasti, in parallelo, ed estrai `name`, `os`, `is_blacklisted`, `country`.

5. Per ogni `srv_ip` valuta, sulla base di tutti i dati raccolti dal punto 1 al 4, se è un servizio AI. Se l'utente ha indicato un servizio preciso, considera AI solo quel servizio; tutto il resto va nel Resto.

6. Somma `bytes`, `packets`, `num_flows` di tutti i `srv_ip` classificati come AI e confrontali con i totali del punto 1 per ottenere le quote.

## Report

- **Risposta diretta**: una frase che risponde alla domanda in modo chiaro e leggibile — quanti MB vanno a sistemi AI, quanti in tutto, in che percentuale e su quante connessioni.

- **Tabella 1 — Server AI** (ordinata per traffico decrescente): ogni riga è un singolo server AI identificato.
  `IP | Provider | Flussi | Pacchetti | Traffico (unità opportuna) | Quota%`
  La colonna Quota% è la percentuale di byte di quel server sul `total_bytes` del punto 1.

- **Tabella 2 — Confronto per provider** (separata): solo i provider AI identificati più una riga Resto che aggrega tutto il resto. Non elencare provider non-AI.
  `Provider | Flussi | Pacchetti | Traffico (unità opportuna) | Quota%`
  — una riga per ogni provider AI identificato
  — Resto (tutto il traffico non AI, aggregato)

- **Conclusione**: volume AI totale, percentuale sui byte totali e numero connessioni, suddivisi per provider.
