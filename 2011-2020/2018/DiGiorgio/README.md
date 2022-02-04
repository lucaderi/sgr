# eBPFlow

Dipendenze:
  - Python docker module
  - Stessi requisiti del tool originale: https://github.com/SalvatoreCostantino/eBPF_TCPFlow

Uso:
  ```
  eBPFlow.py [-h] [-p PID] [-R RPORT] [-P PORT] [-f FILE] [-d]
  ```
  - -h, --help            messaggio di help
  - -p PID, --pid PID     lista di PIDs (separati da virgola) da tracciare
  - -R RPORT, --rport RPORT
                        porte da tracciare in un intervallo
  - -P PORT, --port PORT  lista di porte (separate da virgola) da tracciare
  - -f FILE, --file FILE  scrive output su un file
  - -d                    avvia la sonda in modalità docker (traccia info sui container)

Esempi:
  ``` 
  ./eBPFlow.py -p 181         # only trace PID 181 
   
  ./eBPFlow.py -p 181,2342    # only trace PID 181 and 2342 
 
  ./eBPFlow.py -P 80          # only trace port 80
  
  ./eBPFlow.py -P 80,81       # only trace port 80 and 81 
  
  ./eBPFlow.py -R 80,100      # only trace ports in [80,100] 
  
  ./eBPFlow.py -f <filepath>  # write output to file at <filepath> 
  
  ./eBPFlow.py -d             # enable docker mode 
  ```
