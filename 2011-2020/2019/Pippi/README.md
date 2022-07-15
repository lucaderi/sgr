# GDR
Progetto per Gestione di Reti 2019

Istruzioni

    Compilazione: make

    Test: make test
        Per terminare gli agent dopo il test usare la script killall.sh

Il file di configurazione conf.ini ha valori di default, se occorre modificarlo
è necessario mantenere lo stesso ordine dei tag:
1) DATABASE
2) ORG
3) BUCKET
4) TOKEN
5) PATH
6) PORT

bandwidth_utilisation.json è un modello di dashboard per la visualizzazione dei dati
da importare su InfluxDB.
