# Raspberry Pi Temp :fire:
Il progetto consiste nel monitoraggio del sensore di temperatura (DS18B20) collegato tramite GPIO ad un Raspberry Pi.

![DS18B20](img/sensor.jpg?raw=true "DS18B20")

## SNMP :satellite:
Sul raspberry pi è installato un agent snmp opportunamente  [configurato](snmp/snmpd.conf) per restituire, quando interrogato, il valore della temperatura corrente presente nella stanza.

  ### Installazione
  ```sh
  apt install snmp snmp-mibs-downloader
  ```
  Ora, modifica il file ```/etc/snmp/snmp.conf```
  Commenta la riga:
  ```
  mibs :
  ```
  ... in questo modo:
  ```
  # mibs :
  ```

  ### Utilizzo
  ```sh
  snmpget -v1 -c public raspberrypi-simone.ddns.net nsExtendOutputFull.\"temp\"
  ```
  
## RRD :file_folder:
Lo script [tempManager](tempManager.sh) utilizza un database di tipo Round-Robin, è possibile installarlo tramite il seguente comando:

```sh
apt install rrdtool
```

All'interno dello script è possibile configurare il path relativo al file-database con estensione ```.rrd```, modificando la variabile ```RRD_DB```. Il database generato contene i valori della temperatura e la previsione attesa (in totale 4 valori), aggiornati ogni 5 minuti. Contiene dati raw, per le ultime 12 ore, la media di 1 ora per 1 giorno e la media di 1 giorno, per i 7 giorni precedenti.

## Previsione :crystal_ball:
In questo [file](double_exponential_smoothing.py) è presente l'algoritmo Double Exponential Smoothing eseguito dallo [script](tempManager.sh) principale ogni 5 minuti. Prende in input i valori della temperatura nelle 2 ore precedenti e restituisce una stima del valore successivo ed un intervallo di confidenza, ossia un range di valori in cui siamo abbastanza sicuri che si trovi il vero valore. L'algoritmo è configurabile atrraverso tre fattori:

Smoothing Factor 0 < ```alpha``` < 1,  aumentando alpha il calcolo della stima tiene conto dei valori più recenti e "dimentica" quelli più lontani nel tempo.

Trend Factor 0 < ```beta``` < 1, aumentando beta il calcolo della stima è inluenzato dall'andamento crescente o decrescente della serie temporale nel recente passato.

Valore ```z```, determina l'intervallo di confidenza in base alla probabilità con cui vogliamo stimare il valore futuro. Questa è la tabella dei possibili valori:

| Intervallo di <br> confidenza | Z |
| :-------------: |:-------------:|
| 80% | 1,282 |
| 85% | 1,440 |
| 90% | 1,645 |
| 95% | 1,960 |
| 99% | 2,576 |
| 99,5% | 2,807 |
| 99,9% | 3,291 |

## Avviso Telegram :mailbox_with_mail:
Lo script [tempManager](tempManager.sh) ogni 5 minuti salva la temperatura corrente e la relativa previsione cioè i tre valori restituiti dall'algoritmo Double Exponential Smoothing, nel database rrd. Se il valore della temperatura corrente non è all'interno dell'intervallo di confidenza, allora viene inviato un alert nel canale telegram [Temperature](https://t.me/Temperature_DS18B20). Inoltre se la tempertura supera il limite massimo consentito, configurabile dalla variabile ```MAX_LIMIT```, anche questo evento è opportunamente segnalato nel canale.

## Temp Manager bot :zap:
Il bot Telegram [Temp Manager](https://t.me/tempManagerBot) è utilizzato all'interno del canale per inviare gli avvisi.
Ho utilizzato la libreria python [python-telegram-bot](https://python-telegram-bot.org/) all'interno dello script [tempManagerBot](tempManagerBot.py) per aggiungere al bot il comando ```/temp``` che restituisce la temperatura corrente nella stanza.

### Installazione
```sh
pip install python-telegram-bot --pre
```

## Sito Web :earth_africa:
Sul raspberry pi è presente il Web Server nginx. Visitando il sito [raspberrypi-simone.ddns.net](http://raspberrypi-simone.ddns.net) è possibile visualizzare la temperatura corrente ed i grafici generati dal database rrd.
