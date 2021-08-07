# Introduzione

Lo scopo di questo progetto è l'implementazione di un sistema di individuazione di anomalie in serie temporali che rispettano una distribuzione normale.

Il sistema va calibrato su una porzione della serie temporale ritenuta accettabile dall'utente e delimitata da 2 timestamp. La calibrazione consiste nel calcolo di media e deviazione standard del campione.
A questo punto il sistema è in grado di individuare automaticamente gli outliers, ovvero valori che si discostano di 3 volte la deviazione standard dalla media.

Il sistema implementa anche un altro metodo di individuazione di anomalie basato sulla [regola 68-95-99,7](https://it.wikipedia.org/wiki/Regola_68-95-99,7), una regola empirica per cui il 68%, il 95% e il 99,7% dei valori si trovano rispettivamente all'interno di 1, 2 e 3 deviazioni standard dalla media.

La regola stabilisce anche che il 4,2% dei valori ricade tra 3 sigma e 2 sigma dalla media e che il 27,2% ricade tra 2 sigma e sigma dalla media.

Questo significa che la probabilità che:

- 50 letture di fila si trovino dentro sigma 1 è di 0,682^50 = 4*10<sup>-9</sup>.
- 15 letture di fila si trovino tra sigma e 2 sigma è di 0.272^15 = 3*10<sup>-9</sup>.
- 6 letture di fila si trovino tra 2 sigma e 3 sigma è di 0.042^6 = 5*10<sup>-9</sup>.

Se riteniamo che 10<sup>-9</sup> sia sufficientemente poco probabile, possiamo ritenere anomale serie temporali che presentano questo tipo di misurazioni.

# Dipendenze

Per poter compilare il progetto è necessario un compilatore C, `cmake`, `libxml2`, `librrd` e `argp`.

Su Debian e derivate è sufficiente lanciare `sudo apt install build-essential cmake libxml2-dev librrd-dev`.

# Compilare

È possibile compilare tramite CMake.

1. Creare una cartella per la compilazione. `mkdir build`
2. Entrare nella cartella `cd build`
3. Eseguire cmake: `cmake ..`
4. Lanciare `make`

# Eseguire

Il programma richiede che vengano specificati i seguenti parametri:

- `-s` o `--start` per indicare il timestamp di inizio della porzione di serie temporale da apprendere
- `-e` o `--end` per indicare il timestamp di fine della porzione di serie temporale da apprendere
- un percorso al file RRD da analizzare

Parametri opzionali:

- `-r` o `--rrd` per indicare quale database RRA da analizzare, il primo se non specificato
- `-v` o `--verbose` per l'output verboso

# Test

Il programma è stato testato sul [file rrd fornito](172.16.67.87_tengigabitethernet_1_7.rrd).

Esempio di output:

```
./anomalydetect -r 0 -s 1622487000 -e 1622493600 172.16.67.87_tengigabitethernet_1_7.rrd
Outliers detected from 1622568000 to 1622571300 (10 consecutive readings outside sigma3 and mean 6924093.829720)
Anomaly from 1622573100 to 1622574300 (10 consecutive readings inside sigma3 and mean 13132283.749210)
Outliers detected from 1622577600 to 1622577900 (1 consecutive readings outside sigma3 and mean 8949460.702300)
Anomaly from 1622591700 to 1622592300 (8 consecutive readings inside sigma3 and mean 12098494.210125)
Outliers detected from 1622595300 to 1622595600 (1 consecutive readings outside sigma3 and mean 8305706.261800)
Anomaly from 1622603400 to 1622605200 (12 consecutive readings inside sigma3 and mean 14139797.009833)
Anomaly from 1622614500 to 1622617500 (16 consecutive readings inside sigma3 and mean 11764601.173250)
Anomaly from 1622628900 to 1622630700 (12 consecutive readings inside sigma3 and mean 14596244.574250)
Anomaly from 1622644500 to 1622645400 (9 consecutive readings inside sigma3 and mean 15182449.454111)
Outliers detected from 1622649000 to 1622650500 (5 consecutive readings outside sigma3 and mean 7764077.978900)
Anomaly from 1622655600 to 1622655900 (7 consecutive readings inside sigma3 and mean 14695301.114000)
Outliers detected from 1622657100 to 1622657700 (2 consecutive readings outside sigma3 and mean 8641357.916450)
Outliers detected from 1622659500 to 1622660700 (3 consecutive readings outside sigma3 and mean 8327747.263133)
Anomaly from 1622692200 to 1622695200 (16 consecutive readings inside sigma3 and mean 14482306.982188)
Anomaly from 1622698200 to 1622699400 (10 consecutive readings inside sigma3 and mean 12988525.956200)

```
