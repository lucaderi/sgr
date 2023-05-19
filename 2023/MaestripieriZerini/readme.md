# Estensione di nDPI con predict_linear di Prometheus
Niccolò Maestripieri <n.maestripieri@studenti.unipi.it> 
Gioele Zerini <g.zerini1@studenti.unipi.it>

## Introduzione
[nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/) è una libreria open-source utilizzata per la Deep Packet Inspection. Noi l'abbiamo estesa con la funzione predict_linear descritta nell'API [Prometheus](https://prometheus.io/docs/prometheus/latest/querying/functions/#predict_linear), che permette di predirre il valore futuro di una serie temporale utilizzando la [regressione lineare semplice](https://en.wikipedia.org/wiki/Simple_linear_regression). Per essere conformi alle specifiche di nDPI abbiamo inoltre realizzato una funzione di test da inserire nella libreria. Infine per avere un ulteriore riscontro sul corretto funzionamento del programma abbiamo realizzato due tool che predicono l'utilizzo futuro di memoria e disco.

## Algoritmo
Il prototipo della funzione che abbiamo implementato è il seguente:
``` c
 int ndpi_predict_linear(u_int32_t *values, u_int32_t num_values, u_int32_t predict_period, u_int32_t *predicted_value, float *c, float *m);
```
Possiamo distinguere i parametri di input:
- values: array di valori interi
- num_values: numero di elementi dell'array
- predict_period: periodo del punto da predirre, indica la distanza del punto da predirre dall'ultimo punto contenuto nell'array

E quelli di output:
- predicted_value: valore predetto
- c: parametro della retta di regressione che indica l'intersezione della retta con l'asse y
- m: parametro della retta di regressione che indica la pendenza della retta

La funzione restituisce 0 se il calcolo va a buon fine, altrimenti -1.

Per predirre il valore abbiamo usato la regressione lineare semplice, quindi abbiamo calcolato i parametri della retta di regressione relativa alla serie temporale rappresentata dall'array values. Per calcolare questi parametri abbiamo dovuto calcolare le medie dei valori lungo l'asse x (il tempo, rappresentato dagli indici dei valori dell'array) e lungo l'asse y (i valori dell'array values). Per questi valori abbiamo inoltre calcolato la rispettiva deviazione standard e la loro covarianza.

A questo punto si possono calcolare i parametri alfa e beta, che nel protipo della funzione si chiamano rispettivamente c e m. Le formule sono le seguenti:
$$\alpha = \overline{y} - \left( \beta \overline{x} \right)$$ 
$$\beta = r_{xy} \frac {s_{y}} {s_{x}}$$
Dove:
 - $\overline{y}$ = media dei valori lungo l'asse y
 - $\overline{x}$ = media dei valori lungo l'asse x
 - $\{s_{y}}$ = deviazione standard dei valori lungo l'asse y
 - $\{s_{x}}$ = deviazione standard dei valori lungo l'asse x
 - $r_{xy}$ = coefficiente di correlazione tra x e y

Con i parametri alfa e beta possiamo scrivere la retta di regressione nella forma $y = \alpha + \beta * x$ e utilizzarla per predirre il valore calcolando la y del punto che ha come x l'espressione: predict_period + num_values - 1

### Casi limite
I casi in cui l'algoritmo può fallire sono principalmente due:
- parametri di input sbagliati: array non definito o con meno di due elementi, predict_period < 1
- deviazione standard dei dati uguale a 0: questo non permette di calcolare i parametri della retta di regressione, e di conseguenza di fare la predizione. Un esempio che porta a questa situazione è il caso in cui tutti i dati della serie temporale sono uguali fra loro.

## Fase di compilazione
Su Ubuntu/Debian:
per compilare correttamente il programma è necessario accertarsi di avere git installato sulla propria macchina e successivamente effettuare le seguenti operazioni da linea di comando:
``` c
 cd <Path to Progetto-Gestione-di-reti>
 git clone https://github.com/ntop/nDPI.git
```
Dopodiché sarà necessario eseguire ``` cd nDPI ``` e seguire la fase di compilazione della libreria presente nella guida di [nDPI](https://github.com/ntop/nDPI/blob/bfe79243bc46a9d5357e72ed30e9d84fb3069530/README.md).
Dopo basterà eseguire  ``` cd .. ``` e nuovamente ``` make ``` per ottenere i file eseguibili. Quindi digitando:
- ``` ./main.out ``` si potrà eseguire la funzione di testing del programma;
- ``` ./tool.out ``` si potrà eseguire il tool per la memoria;
- ``` ./toolDisk.out ``` si potrà eseguire il tool per il disco.

## Funzione di test
Abbiamo sviluppato una funzione di test da inserire all'interno del file ndpiReader.c, per testare il corretto funzionamento di ndpi_predict_linear. La nostra funzione di test definisce un'array di 10 valori e predice il valore dell'eventuale quindicesimo punto dell'array. Se il calcolo va a buon fine stampa il valore predetto ed i parametri della retta di regressione, altrimenti un messaggio di errore.

![image](https://github.com/GioZerini/Progetto-Gestione-di-reti/assets/91292627/6919fb40-21f9-4f44-9db9-2c327bf0baaa)

Per modificare i parametri di input come l'array values e predict_period si deve modificare direttamente il codice sorgente della funzione, quindi senza modifiche al codice sorgente i risultati della funzione di test saranno sempre gli stessi

## Tool
Per verificare ulteriormente il funzionamento del progetto abbiamo realizzato due tool che permettono di predirre l'uso del disco/memoria. I tool sono realizzati con la stessa struttura, cioè vengono raccolti 10 dati di utilizzo del disco/memoria a intervalli regolari di 10 secondi, in modo da avere una serie temporale da usare per la predizione. Dopodichè usando la ndpi_predict_linear prediciamo l'utilizzo del disco/memoria tra 1 minuto.

Per quanto riguarda il tool che predice l'utilizzo del disco è possibile che si verifichi il caso in cui tutti i valori della serie sono uguali, dato che l'utilizzo del disco difficilmente cambia in tempo ravvicinato, quindi si potrebbe verificare il caso limite in cui la deviazione standard dei dati è uguale a 0

Output visualizzato dai tool in caso di calcolo andato a buon fine:

![memory](https://github.com/GioZerini/Progetto-Gestione-di-reti/assets/91292627/a0e1a375-0b3f-4ecb-8aec-7a31634cf268)

![disk](https://github.com/GioZerini/Progetto-Gestione-di-reti/assets/91292627/310ee42d-a076-4f45-8108-a24f11705a45)
