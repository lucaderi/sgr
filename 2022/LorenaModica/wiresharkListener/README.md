# WiresharkListener
Questo codice è implementato su Ubuntu 21.10 con Lua versione 5.2.4 testato su Wireshark versione 3.4.7 

WiresharkListener consiste nell' integrare un listener in Wireshark che, dato un host X , fa una statistica degli host contattati da X , stima quante volte X è stato contattato a sua volta e il numero di pacchetti diversi scambiati tra X e gli altri host.
Le approssimazioni vengono calcolate sfruttando l' algoritmo HyperLogLog e i risultati vengono visualizzati in una finestra all' interno di Wireshark.

# Prerequisiti

* Wireshark

# Istruzioni

* Aprire Wireshark -> Aiuto -> Informazioni su Wireshark -> Cartelle
* Aprire il path relativo a plugin personali.
* Scaricare il contenuto nella cartella dei plugin personali con il comando: 
  
  ```
  git clone https://github.com/LorenaModica/wiresharkListener.git
  
  ```
* Avviare Wireshark come root

Maggiori informazioni sono reperibili nella relazione

