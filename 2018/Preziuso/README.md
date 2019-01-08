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

## ESECUZIONE

Da terminale, accedere alla directory dov'è situato il file `arpmap.py` ed eseguire
```bash
python3 arpmap.py <interface>
```
dove `<interface>` va sostituito con il nome dell'interfaccia da esaminare. È possibile omettere il parametro <interface>, in tal caso verrà segnalato l'utilizzo dell'interfaccia del wifi (`en0`), impostata come default.

## INTERFACCE

Per visualizzare la lista delle interfacce o aggiungerne/rimuoverne la disponibilità, aprire il file `interfaces.py` nella stessa directory di `arpmap.py`, e modificare il dizionario `interfaces` tenendo presente che:

* la **chiave** è arbitraria e costituisce il **parametro `<interface>`** da passare ad `arpmap.py`
* il **valore** è il **codice dell'interfaccia** che si vuole monitorare quando indicata la corrispondente chiave (es. `eth0`, `eth1`, `en0`, ...)
