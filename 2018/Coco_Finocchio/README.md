# HOKER - a local network HOst tracKER

HOKER è un tool per il monitoraggio degli host connessi ad una rete locale basato sulla libreria pcap che sfrutta il protocollo ARP per immagazzinare informazioni come:

- Associazioni MAC-IP
- Connessioni e disconnessioni dalla rete

## Istruzioni per l'utilizzo
Compilare con:
```sh
$ make
```
Eseguire con:
```sh
$ sudo ./hoker <interfaccia-di-rete>
```

>Mario Coco 517558
>Federico Finocchio 516818
