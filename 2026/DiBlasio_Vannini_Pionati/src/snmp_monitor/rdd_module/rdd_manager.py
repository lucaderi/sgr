import os
import csv
import time
import rrdtool


def parse_rrd_filename(filename: str) -> tuple[str, str]:
    """Restituisce IP e indice di interfaccia a partire da un nome di file RRD.

    Formato atteso: 192_168_1_1_if1.rrd -> ("192.168.1.1", "1")
    """
    stem = os.path.basename(filename)[:-4]
    ip_part, iface_part = stem.rsplit("_if", 1)
    ip_address = ip_part.replace("_", ".")
    return ip_address, iface_part


def create_rrd_path(agent_ip:str,if_index:str)-> str :

    #crea il filename per l'agent 

    ip=agent_ip.replace(".","_")
    filename=f"rrd_data/{ip}_if{if_index}.rrd"
    return filename

def create_rrd(path:str, start_time:int|None=None, overwrite:bool=False) :

    # Se il file esiste già e dobbiamo ricrearlo, lo rimuoviamo prima di ricrearlo
    if overwrite and os.path.exists(path):
        os.remove(path)

    # Creo la cartella dei file RRD se non esiste
    os.makedirs("rrd_data", exist_ok=True) 

    # Se non viene passato un start_time, uso un valore leggermente precedente al momento attuale
    if start_time is None:
        start_time = int(time.time()) - 120

    rrdtool.create(
        path,
        "--step","60",    #polling ogni 60s
        "--start", str(start_time),
        "DS:if_oper_status:GAUGE:120:0:U",  #DS : nome : tipo : heartbeat : min : max /gauge
        "DS:if_octets_in:COUNTER:120:0:U",  #il Gauge server per valori fissi, counter per valori crescenti
        "DS:if_octets_out:COUNTER:120:0:U", 
        "DS:if_in_errors:COUNTER:120:0:U",
        "DS:if_out_errors:COUNTER:120:0:U",
        "RRA:AVERAGE:0.5:1:1440" # definisce come archiviare i dati nel tempo
    )

def update_rrd(path:str,row:dict) -> bool:

    # Costruisco la stringa di aggiornamento nel formato richiesto da RRDtool
    stringa=f"{row['timestamp']}:{row['if_oper_status']}:{row['if_in_octets']}:{row['if_out_octets']}:{row['if_in_errors']}:{row['if_out_errors']}"
    print(f"UPDATE: {path} -> {stringa}")

    try:
        rrdtool.update(path, stringa)
        return True
    except rrdtool.OperationalError as e:
        print(f"Saltato: {e}")
        # Se l'aggiornamento fallisce per timestamp troppo vecchio, ricreo il file con un start_time coerente
        timestamp = int(row['timestamp'])
        try:
            create_rrd(path, start_time=timestamp - 120, overwrite=True)
            rrdtool.update(path, stringa)
            return True
        except rrdtool.OperationalError as retry_error:
            print(f"Retry fallito: {retry_error}")
            return False

def process_row(row:dict):

    # Ricavo il path del file RRD per questo interfaccia
    path= create_rrd_path(row['agent_ip'],row['if_index'])
    timestamp = int(row['timestamp'])

    # Se il file non esiste, lo creo prima di inserire i dati
    if not os.path.exists(path):
        create_rrd(path, start_time=timestamp - 120)
        update_rrd(path,row)
        return

    # Se l'aggiornamento fallisce, ricreo il file e riprovo
    if not update_rrd(path,row):
        create_rrd(path, start_time=timestamp - 120, overwrite=True)
        update_rrd(path,row)


if __name__ == "__main__":
    with open("metrics.csv", "r") as f:
        reader = csv.DictReader(f)
        rows = sorted(reader, key=lambda r: int(r["timestamp"]))
        print(f"Righe lette: {len(rows)}")
        for row in rows:
            process_row(row)