Alessandro Fico Matricola 654772
Progetto NetFlow v5 in C

Requisiti

- GCC (o altro compilatore C)
- Net-SNMP utilities (`snmptrap`) per inviare SNMP trap dalla riga di comando

Compilazione

make

Esempio di esecuzione

1) Avviare il collector (sostituire l'IP della destinazione SNMP trap):

./collector --trap-ip 192.0.2.10 --listen-port 2055 --blacklist blacklist.txt --community public

Nota: il collector ha un valore di default per l'IP della trap definito a compile-time come `TRAP_IP` (attualmente `192.0.2.1`). Per cambiare il valore di default senza usare l'opzione a run-time, ricompila con ad esempio:

```bash
gcc -DTRAP_IP=\"198.51.100.5\" -o collector collector.c
```

2) Inviare un pacchetto di test:

./flow_generator 127.0.0.1 2055 10.0.0.5 192.0.2.100

Note

- Il collector chiama `snmptrap` per inviare trap SNMP v1; assicurati che Net-SNMP sia installato e che il comando sia disponibile.
- Il codice è minimale e pensato per scopi didattici: per uso in produzione, gestire memory leaks, segnali, validazioni e TLS/SNMPv3.
