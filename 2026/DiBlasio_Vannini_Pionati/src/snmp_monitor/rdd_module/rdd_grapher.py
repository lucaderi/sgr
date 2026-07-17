import os
import rrdtool
from snmp_monitor.rdd_module.rdd_manager import parse_rrd_filename

def graph_traffic(path:str) :

    # Creo la cartella dove salvare i grafici PNG se non esiste
    os.makedirs("rrd_graphs", exist_ok=True)

    rrd_path = f"rrd_data/{path}"
    png_path = f"rrd_graphs/{path.replace('.rrd', '.png')}"

    rrd_path_abs = os.path.abspath(f"rrd_data/{path}")
    print(f"File esiste: {os.path.exists(rrd_path_abs)}")
    print(f"DEF: DEF:traffic_in:{rrd_path_abs}:if_octets_in:AVERAGE")

    ip,inf = parse_rrd_filename(path)

    # Genero il grafico con un intervallo di 1 ora e una linea più leggibile
    # così i punti non spariscono se i campioni arrivano con un po' di ritardo
    rrdtool.graph(
        png_path,
        "--start", "-1h", #inizio tempo dati raccolti
        "--end", "now", #fine tempo dati raccolti
        "--title", f"Traffico intefaccia{inf} di {ip}", #titolo grafo
        "--vertical-label", "bytes/s", #testo asse verticale
        "--width", "800", #larghezza
        "--height", "300", #altezza
        "--slope-mode", # fa in modo che la linea sia più leggibile
        f"DEF:traffic_in={rrd_path_abs}:if_octets_in:AVERAGE", #valori mostrati
        f"DEF:traffic_out={rrd_path_abs}:if_octets_out:AVERAGE",
        f"DEF:status={rrd_path_abs}:if_oper_status:AVERAGE",
        "CDEF:is_down=status,2,EQ,1000000,0,IF",
        "AREA:is_down#FF000080:Interface Down",
        "LINE1:traffic_in#0000FF:Traffico In", 
        "AREA:traffic_out#00FF0080:Traffico Out",
    )

def generate_all_graph() :
        
    os.makedirs("rrd_graphs", exist_ok=True) 
    lista=[f for f in os.listdir("rrd_data/") if f.endswith(".rrd")]

    for file in lista :
        graph_traffic(file)


if __name__ == "__main__" :
    generate_all_graph()