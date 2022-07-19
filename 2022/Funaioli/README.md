# Analisi della skewness di una serie temporale

## Introduzione

![skewness example graph](./images/example.png)

Il progetto consiste, dato un file rrd, nel determinare i punti in cui la serie temporale assume dei valori che ne aumentano la skewness. Come definizione di _skewness_ ho considerato quella riportata alla pagina [Skewness](https://en.wikipedia.org/wiki/Skewness). La formula usata è quella proposta al seguente [link](https://en.wikipedia.org/wiki/Skewness#Sample_skewness), cioè:

![formula](./images/formula.svg)

La formula viene applicata ad un intervallo di valori di ampiezza `size` punti e l'intervallo viene traslato di `transl` punti dopo ogni computazione del valore di skewness.

Il progetto si compone di uno script bash e di un programma in C. Lo script si occupa di creare un file rrd e di riempirlo di punti. I punti vengono aggiunti in modo da creare delle situazioni in cui la serie temporale è skew. Lo script prende in input un intero tra 0 e 1 per creare i punti da inserire. Il programma C, dato il path al file rrd da analizzare, si occupa di riportare i punti in cui la skewness della serie temporale supera una certa soglia. In particolare i parametri presi in input dal programma C sono:
- il tempo di inizio e di fine di analisi del file rrd
- l'ampiezza `size` dell'intervallo
- il numero di punti `transl` di cui traslare l'intervallo
- la soglia oltre cui riportare i valori di skewness calcolati
- il path al file rrd da analizzare

## Compilazione ed esecuzione

L'unica dipendenza è la libreria [librrd](https://github.com/oetiker/rrdtool-1.x), usata per accedere ai file rrd. Per la compilazione:
```
gcc -L /usr/lib/ -lrrd -lm skewness.c -o skewness
```
Per l'esecuzione è sufficiente:
```
./skewness -f <path-to-rrd>
```
Un esempio di esecuzione potrebbe essere:
```
./create_rrs.sh 1
./skewness -t 65 -n 15 -T 3 -f skeweddata.rrd
```

## Test

Il progetto è stato testato con diversi valori per i parametri `size` e `transl`. In particolare, all'aumentare di `size`, aumenta anche il valore assoluto dei valori di skewness calcolati e, di conseguenza, il numero di valori riportati. Il parametro di soglia è specifico per ogni file rrd: è stato scelto un valore di default di 100, ma in base a quanto la serie temporale è skew e a quali valori si scelgono per `size` e `transl` potrebbe essere necessario modificare il valore di soglia.

