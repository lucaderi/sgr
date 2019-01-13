# arpmap

## Prerequisiti

* Assicurarsi di aver installato Python 3 sulla propria macchina (per lo sviluppo è stata utilizzata la release 3.7.2).
* Installare l'ultima versione della libreria `pyshark`.
	
**Per tutte le piattaforme**
Installazione diretta da terminale 
			
```bash
pip3 install pyshark
```
o da GitHub:
```bash
git clone https://github.com/KimiNewt/pyshark.git
cd pyshark/src
python3 setup.py install
```

In caso di problemi con l'installazione di `pyshark`, si rimanda alla relativa documentazione: https://github.com/KimiNewt/pyshark .

## Esecuzione

Da terminale, accedere alla directory dov'è situato il file `arpmap.py` ed eseguire
```bash
python3 arpmap.py <interface>
```
dove `<interface>` va sostituito con l' **identificativo** dell'interfaccia da esaminare<sup>[1](#interfaces)</sup>. È possibile omettere il parametro <interface>, in tal caso verrà segnalato l'utilizzo dell'interfaccia wifi (`en0`), impostata come default.

<a name="interfaces">1</a>: Per controllare la lista delle interfacce disponibili sul proprio sistema, se si ha Wireshark installato sulla macchina, eseguire il comando
```bash
wireshark -D
```
da linea di comando.