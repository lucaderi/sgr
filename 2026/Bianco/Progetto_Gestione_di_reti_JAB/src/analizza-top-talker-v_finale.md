Usa questa skill quando l'utente chiede: chi mi sta mandando traffico? chi fa più traffico? c'è un host sospetto che sta mandando tanto traffico? analizza il traffico in ingresso. Oppure le stesse domande con un IP specifico: chi sta mandando traffico verso <ip>? c'è un host sospetto che sta mandando tanto traffico verso <ip>? chi fa più traffico verso <ip>? Analizza i flussi attivi e identifica quali host remoti stanno inviando più dati verso il computer locale, valutando se il comportamento è anomalo.

> Per aggiungere il grafico al report, includere nella richiesta: **"con grafico"** o **"con visualizzazione"** (es. "chi mi sta mandando traffico con grafico?").

## Pipeline

### Stadio 1 — Identifica gli IP locali
Se l'utente ha specificato un IP nella richiesta, `local_ip` = quell'IP e procedi direttamente allo Stadio 2.
Altrimenti chiama `get_interface_addresses()`, rimuovi il prefisso CIDR (es. `/32`, `/128`) da ciascun indirizzo, elencali all'utente e chiedi quale vuole usare. Non proseguire agli stadi successivi prima di aver ricevuto la risposta. Non riutilizzare un IP scelto in invocazioni precedenti della skill nella stessa conversazione: chiedi sempre.
`local_ip` = l'indirizzo scelto dall'utente.

### Stadio 2 — Raccogli i flussi in arrivo
Chiama `get_live_flows_for_host` con argomento `ip=local_ip` e `max_flows=200`.
Per ogni flusso, il traffico IN ARRIVO è:
- se `local_ip == srv_ip` → bytes_in = `bytes_cli2srv`, paese = `cli_country`
- se `local_ip == cli_ip` → bytes_in = `bytes_srv2cli`, paese = `srv_country`

L'host remoto è l'IP opposto a `local_ip`. Escludi `local_ip` dai risultati.
Aggrega per host remoto: somma `bytes_in` su tutti i flussi dello stesso IP. Prendi il paese più frequente e l'`app_proto` più frequente per quell'IP.
`bytes_in` = traffico che l'host remoto ha inviato VERSO la macchina locale — non il contrario.

La notazione `cli_ip → srv_ip` nel CSV indica chi ha aperto la connessione, non la direzione del traffico dati. Quando local_ip è `cli_ip`, è comunque il `srv_ip` remoto a inviare i dati verso local_ip (`bytes_srv2cli`). Usa sempre questa logica anche quando descrivi singoli flussi nel report — il soggetto è sempre l'host remoto che invia verso local_ip.

### Stadio 3 e 4 — Eseguire in parallelo solo dopo che Stadio 2 è completato

**Stadio 3 — Arricchimento**
- `get_host_info` per ogni host remoto unico raccolto in Stadio 2 → score, alert attivi, is_blacklisted

**Stadio 4 — Topologia LAN**
- `discover_lan` passando `ifid` e `ifname` dell'interfaccia attiva forniti nel system prompt → mappa completa dei dispositivi sulla LAN (MAC, `hostname`, manufacturer, device_type)

### Stadio 5 — Ragionamento AI
L'analisi riguarda SOLO il traffico ricevuto da local_ip (bytes_in). Non commentare il traffico uscente da local_ip.
**Non usare e non menzionare mai**: bytes inviati da local_ip, upload, traffico uscente, bytes.sent di local_ip.

Guarda i dati nel loro insieme e rispondi:
- Chi sta inviando significativamente più degli altri verso local_ip?
- Il volume assoluto ricevuto è rilevante o siamo in una rete silenziosa?
- **Coerenza protocollo/identità**: il protocollo (`app_proto`) è compatibile con l'identità dell'host remoto? Un protocollo incoerente con l'host è un segnale di anomalia indipendentemente dal volume.
- **Volume per protocollo**: il volume di bytes_in è plausibile per quel protocollo? Valuta se la quantità di dati ricevuti ha senso rispetto al protocollo usato.
- **Normalità del volume per quell'host**: il volume ricevuto da quell'host specifico è coerente con il suo ruolo e il tipo di servizio che offre? Un volume anomalo rispetto a ciò che ci si aspetterebbe da quell'host è un segnale da investigare.
- **Score e blacklist**: `is_blacklisted = true` → giudizio **critico** immediato, indipendentemente da volume e protocollo. Score ≥ 50 → da monitorare; score ≥ 100 → priorità massima indipendentemente dal volume.
- Il pattern è sostenuto nel tempo o un burst momentaneo?

Giudizio per ogni host rilevante: **normale** | **da monitorare** | **sospetto** | **critico**

## Report

Prima di produrre il report, costruisci la **classifica globale completa** di tutti gli host remoti ordinati per bytes_in decrescente e assegna a ciascuno un numero progressivo (#1, #2, #3, ...). Questa numerazione è condivisa tra tutte le tabelle del report.

**Tabella top 10** (i primi 10 della classifica globale) — bytes_in = traffico ricevuto dall'host locale DA quell'host:
`# | IP | protocollo | paese | bytes_in | quota% | score | giudizio`

**Tabella dispositivi LAN attivi** (solo i dispositivi da discover_lan il cui IP è presente nei flussi di Stadio 2, cioè stanno comunicando con local_ip in questo momento):
`# | IP | hostname | MAC | manufacturer | device_type | bytes_in`
La colonna `#` è la posizione nella classifica globale completa (non solo top 10) — anche se un dispositivo LAN è al posto 15 o 30, mostra quel numero. Ordina per bytes_in decrescente.
Mostra questa tabella subito dopo la top 10, prima della topologia completa. Se non ci sono dispositivi LAN attivi, ometti la tabella.

**Tabella dispositivi LAN** (tutti i dispositivi da discover_lan):
`# | IP | hostname | MAC | manufacturer | device_type | attivo`

La colonna `#` è la posizione nella classifica globale completa: mostra sempre il numero se il dispositivo è presente nei flussi di Stadio 2, `—` solo se non ha mai comunicato con local_ip.
La colonna `attivo` indica se quel dispositivo ha comunicato con la macchina locale durante l'analisi (IP presente nei flussi di Stadio 2): `✅` se attivo, `—` altrimenti.

Non includere i dispositivi locali nell'analisi o nella valutazione finale — le tabelle sono solo informative.

**Analisi**: per ogni host che si distingue, una valutazione motivata in 2-3 righe.

**Conclusione**: 2-3 righe — chi sta inviando più traffico verso l'host locale? È un problema reale? Cosa fare.

## Note operative
- Score ≥ 50 va segnalato nel report; score ≥ 100 va sempre evidenziato anche con volume basso.
- Nella colonna score: mostra il valore numerico anche se è 0; usa `—` solo se get_host_info non ha restituito dati per quell'host.
- Usa il widget visualize solo se l'utente ha incluso "con grafico" o "con visualizzazione" nella richiesta.
