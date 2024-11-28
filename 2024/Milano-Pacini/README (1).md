
# Analisi dei File di Log per la Sicurezza

Questo progetto analizza i file di log del server web per identificare attività sospette, come tentativi di SQL injection, accesso a URL sospetti, fallimenti di login e tentativi di accesso da fuori dall'Italia. I log vengono raggruppati in base a intervalli di 5 minuti e vengono forniti dati sulle potenziali problematiche di sicurezza.

## Funzionalità

- **Geolocalizzazione IP**: Utilizza la libreria `geoip2` per verificare se un indirizzo IP proviene dall'Italia.
- **Rilevamento SQL Injection**: Identifica potenziali tentativi di SQL injection esaminando le richieste URL per modelli sospetti.
- **Accesso a URL Sospetti**: Identifica richieste che sembrano cercare di accedere a file o risorse sospette.
- **Tentativi di Login Falliti**: Monitora i fallimenti di login consecutivi e segnala indirizzi IP che li generano.
- **Accesso da IP Esterni**: Identifica tentativi di login da indirizzi IP che non appartengono all'Italia.

## Requisiti

- Python 3.x
- Librerie Python:
  - `re`
  - `os`
  - `datetime`
  - `pytz`
  - `geoip2`
  
Per installare le dipendenze, puoi usare il comando:

```
pip install pytz geoip2
```

- Un file di database di geolocalizzazione IP `GeoIP2` (ad esempio `dbip-country-lite-2024-11.mmdb`).

## Come Usare

1. Assicurarsi di avere il file di database di geolocalizzazione IP (`dbip-country-lite-2024-11.mmdb`).
2. Specifica la cartella dei log come argomento da linea di comando:

   ```
   python script.py /percorso/alla/cartella/dei/log
   ```

3. Lo script analizzerà tutti i file di log nella cartella specificata, li ordinerà per data di modifica e avvierà l'analisi di sicurezza.

## Dettagli Tecnici

- **Formato dei Log**: Lo script assume che il formato del log sia simile al seguente:

```
<IP> - - [<timestamp>] "<request>" <status>
```

Dove:
- `<IP>` è l'indirizzo IP della richiesta.
- `<timestamp>` è il timestamp in formato `[giorno/mese/anno:ora:minuti:secondi fuso_orario]`.
- `<request>` è la richiesta HTTP.
- `<status>` è il codice di stato HTTP.

## Contribuire

Se desideri contribuire a questo progetto, sentiti libero di aprire una pull request. Ogni miglioramento è benvenuto!
