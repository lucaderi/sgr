<h2 align="center">
  <strong>GESTIONE DI RETI: Baseline & JA4 Analyzer</strong>
</h2>

**Corso:** Gestione di Reti <br>
**Docente:** Prof. Luca Deri <br>
**Studente:** Andrea Bianucci <br>
**Data:** 11 Settembre 2026

---

### 1. Introduzione e Obiettivi
L'obiettivo principale del progetto è l'analisi del traffico di rete generato da un dispositivo mobile (smartphone) al fine di estrarne una baseline comportamentale (es. a quali server esterni si collega e con quale frequenza). Nello specifico, lo studio mira ad associare le fingerprint crittografiche **JA4** ai domini contattati (SNI) e alle relative applicazioni, sfruttando le capacità di fingerprinting della libreria open-source **nDPI**.

Il lavoro prevede inoltre l'integrazione di un modello di **Intelligenza Artificiale (LLM)** eseguito interamente in locale, per consentire di rispondere (tramite AI) a domande sul traffico tramite linguaggio naturale, tutelando contestualmente la privacy dei log di rete.

### 2. Metodologia e Raccolta Dati
La fase di *data collection* è stata condotta rispettando rigorosamente i seguenti step:
1. Disabilitazione della rete dati cellulare e collegamento dello smartphone a un hotspot generato dal portatile.
2. Abilitazione sul portatile della cattura dei dati su wifi in modo da vedere il traffico del cellulare.
3. Avvio della cattura del traffico con **Wireshark**, generando il file `traffico_telefono.pcapng` fornito nel repository.
4. Generazione di traffico reale iniziando ad aprire un po' di applicazioni installate sul dispositivo (es. Instagram, Spotify, WhatsApp, YouTube, TikTok).
5. Elaborazione offline del file PCAP tramite l'eseguibile `ndpiReader` per l'estrazione delle informazioni applicative, dei metadati TLS/QUIC e dei fingerprint JA4.

### 3. Sviluppo del Software di Analisi
Per processare l'output di nDPI, è stato sviluppato uno script in Python (`analyzer.py`) che esegue il parsing del testo e costruisce dinamicamente una **Knowledge Base** (baseline)..

#### 3.1 Estrazione e Mappatura dei Dati
Tramite espressioni regolari (RegEx), lo script isola ogni singolo blocco di flusso estraendo:
* **Host Sorgente:** Indirizzo IP del dispositivo (es. `192.168.2.2`).
* **Protocollo L5 (Applicazione):** Riconosciuto nativamente da nDPI (es. `QUIC.Instagram`, `TLS.Spotify`).
* **Dominio / SNI:** Hostname richiesto in chiaro.
* **Fingerprint JA4:** Impronta crittografica del client/sessione (sia per traffico TLS standard che per HTTP/3 su QUIC).
* **Contatori di Frequenza:** Lo script tiene traccia della mole di connessioni, registrando quante volte un'applicazione o un dominio specifico vengono contattati dall'host, permettendo di quantificare il comportamento standard del dispositivo.

#### 3.2 Integrazione con Intelligenza Artificiale Locale
Per rispondere in modo dinamico a domande esplorative sul traffico (es. *"Quali domini sono contattati da una fingerprint JA4 specifica?"*), lo script è dotato di un modulo di interfacciamento verso un **Large Language Model (LLM)** ospitato in locale.
Attraverso un Local API Server compatibile con lo standard OpenAI (tramite l'applicativo *Bionic/LM Studio*), lo script compatta l'intera baseline estratta in formato JSON e la invia come contesto al modello LLM. 

### 4. Sintesi Preliminare della Baseline
Dall'elaborazione del file di cattura iniziale `ndpi_output.txt`, l'algoritmo ha censito la seguente topologia di traffico per l'host target:
* **IP Dispositivo Mobile:** `192.168.2.2` (IPv4) / `fde0:a9bd:1109...` (IPv6)
* **Traffico Analizzato:** ~762 Flussi Unici
* **Impronte JA4 Distinte:** 20 impronte crittografiche
* **Protocolli Dominanti:** QUIC (Instagram, YouTube, WhatsApp, Facebook), TLS (Spotify, Apple)

---

## Manuale Utente: Come eseguire il progetto in locale

I file necessari contenuti nel repository sono:
* `analyzer.py`: Lo script principale di parsing e analisi.
* `ndpi_output.txt`: Il log generato da nDPI su cui lavora lo script.
* `traffico_telefono.pcapng`: Il file di cattura grezzo originale.

### Prerequisiti
* **Python 3.x** installato sul sistema.
* Nessuna dipendenza Python esterna richiesta (lo script usa solo librerie standard: `re`, `os`, `sys`, `json`, `urllib.request`).
* Un software per l'esecuzione di LLM in locale (si consiglia **LM Studio** o **Bionic**).

### Setup dell'Intelligenza Artificiale (Bionic / LM Studio)
Per abilitare la funzionalità di "Chatbot" interattivo basato su IA, è possibile avviare il server locale scegliendo uno dei due metodi seguenti. Si raccomanda l'uso di un modello linguistico efficiente (es. **Gemma 12B QAT**, **Llama 3 8B**, o **Phi-3 Mini** quantizzati).

**Metodo A: Tramite Interfaccia Grafica (GUI)**
1. Aprire Bionic o LM Studio.
2. Aprire la sezione **Local Server** (icona `<->`) e assicurarsi che il modello scelto sia caricato in memoria tramite l'apposito menu a tendina.
3. Avviare il server, che si metterà in ascolto sulla porta di default `1234` (`http://localhost:1234/v1/chat/completions`).

**Metodo B: Tramite Linea di Comando (CLI)**
In alternativa all'interfaccia grafica, è possibile gestire il tutto da un terminale separato:
1. Avviare il server API locale:
    ```bash
    lms server start
    ````
2. Caricare il modello in memoria (il tool proporrà una lista interattiva da cui selezionare il modello desiderato con le frecce direzionali):
    ```bash
    lms load
    ````
3. Spegnere il server
    ```bash
    lms server stop
    ````
4. Liberare memoria RAM
    ```bash
    lms unload --all
    ```

### Esecuzione dello Script
Aprire un terminale nella cartella del repository e lanciare lo script passando come argomento il percorso del file di output generato da nDPI:

```bash
python3 analyzer.py ndpi_output.txt
````
<br>

**Interfaccia**:

```plaintext
=================================================================
       GESTIONE RETI: BASELINE & JA4 ANALYZER       
=================================================================
[*] Dati caricati: 2 host, 20 JA4, 52 domini.

----------------------------------------
 MENU OPERAZIONI:
  1. Quali fingerprint JA4 usa l'host X?
  2. Quali domini/app sono associati alla fingerprint JA4 Y?
  3. Mostra riassunto completo della baseline
  4. Interroga l'Intelligenza Artificiale locale (Bionic)
  5. Esci
----------------------------------------
```
* Opzioni 1-3: Permettono di interrogare in modo deterministico la Knowledge Base o di visualizzare una sintesi testuale completa di come le app, i protocolli e le fingerprint sono correlate[cite: 2].

* Opzione 4 (AI): Permette di interagire in linguaggio naturale in tempo reale (es. "Quali applicazioni ha usato l'IP 192.168.2.2?" o "Generami una classifica delle app più frequenti").
  * Esempio:
    * *Noti qualche fingerprint JA4 che viene utilizzata per contattare un numero insolitamente alto di domini diversi? Secondo te, a livello di sicurezza, indica l'uso di un'applicazione specifica o di una libreria di sistema condivisa da più app?*
      * [AI]:Sulla base dei dati nDPI forniti, si osservano i seguenti fingerprint JA4 con un numero elevato di domini distinti:

        1.  **`q13d0311h3_55b375c5d22e_f2a83c8e78ae`**: Contatta **26 domini** diversi, inclusi servizi di WhatsApp, Apple (iCloud, iTunes, Safari), YouTube, Facebook, Spotify e Google (Firebase).
        2.  **`t13d2013h2_a09f3c656075_7f0f34a4126d`**: Contatta **17 domini** diversi, tra cui WhatsApp, Apple, Google, YouTube e CDN vari.
        3.  **`t13d1313h2_f57a46bbacb6_7f0f34a4126d`**: Contatta **16 domini** diversi, principalmente legati a Spotify e Google.

        **Analisi di sicurezza:**
        L'interazione di un singolo fingerprint con domini appartenenti a ecosistemi così diversi (Apple, Google, Meta, Spotify) indica l'uso di una **libreria di sistema condivisa** o di un **servizio di rete di basso livello** (come un framework di networking comune o un processo di sistema dell'OS). Se fosse un'applicazione specifica, il traffico sarebbe più concentrato sui domini proprietari di quel singolo servizio.