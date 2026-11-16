# Hybrid Multilayer Firewall

Il progetto prevede lo sviluppo di un **Hybrid Multilayer Firewall**, un firewall di rete che analizza il traffico a due diversi livelli e stabilisce se consentire o bloccare i pacchetti.

I due livelli di analisi sono:

- **analisi del pacchetto**: si considerano informazioni come indirizzi IP, protocollo e porte;
- **analisi del flusso**: si mantiene lo stato dei flow e si raccolgono caratteristiche aggregate come numero di pacchetti, quantità di byte trasferiti, durata e frequenza della comunicazione.

L'analisi viene effettuata **localmente e offline**, utilizzando traffico di rete precedentemente catturato e salvato in file PCAP.

Il principale componente di filtraggio è il **Policy Engine**, nel quale viene configurato un insieme di regole utilizzate per confrontare le informazioni relative a pacchetti e flow e produrre una decisione **ALLOW/DROP**.

## Istruzioni d'uso
### Installazione

Clonare il repository ed entrare nella cartella del progetto:

```bash
git clone https://github.com/coosti/hybrid-firewall.git
cd hybrid-firewall
```

### Configurazione dell’ambiente

Creare un ambiente virtuale Python:

```bash
python -m venv venv
```

Attivarlo su macOS/Linux:

```
source venv/bin/activate
```

Su Windows, tramite PowerShell:

```bash
.\venv\Scripts\Activate.ps1
```

Installare le dipendenze:

```bash
python -m pip install -r requirements.txt
```

### Esecuzione

Avviare l’analisi di una cattura eseguendo lo script principale:

 ```bash
python src/main.py data/policy_test_pcaps/01_tcp_handshake_ok.pcap --profile test --json risultato.json
```

Sostituire il percorso della cattura con il file PCAP o PCAPNG da analizzare. 
L’opzione --profile seleziona il profilo (demo, custom o test), mentre --json permette di salvare il report nel file indicato. Le impostazioni dei profili sono modificabili in src/firewall/engine/policy_profile.py.
