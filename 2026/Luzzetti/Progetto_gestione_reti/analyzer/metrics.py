import math
import pandas as pd
from collections import Counter

def shannon_entropy(values):
    """
    Calcola l'entropia di Shannon di una lista di valori discreti.

    Nel progetto viene utilizzata sulle porte di destinazione dei flow TCP e UDP.
    
    Una distribuzione concentrata su poche porte produce un'entropia bassa.
    Una distribuzione distribuita su molte porte produce un'entropia più alta.
    """

    if not values:
        return 0.0

    frequencies = Counter(values)
    total_values = len(values)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / total_values
        entropy -= probability * math.log2(probability)

    return entropy


def build_window_metrics(flows, window_seconds):
    """
    Raggruppa i flow in finestre temporali regolari.

    Ogni flow viene assegnato alla finestra in cui è iniziato, utilizzando il campo start_time.

    Per ogni finestra vengono calcolate le seguenti metriche:

    - new_flow_count: numero di flow iniziati nella finestra;
    - distinct_destination_ports: numero di porte di destinazione distinte osservate nei flow TCP e UDP;
    - distinct_destination_hosts: numero di indirizzi IP di destinazione distinti;
    - port_entropy: entropia di Shannon delle porte di destinazione dei flow TCP e UDP;
    - average_packets_per_flow: numero medio di pacchetti per flow;
    - average_bytes_per_flow: numero medio di byte per flow;
    - average_flow_duration: durata media dei flow iniziati nella finestra.

    Queste metriche sono pensate per evidenziare comportamenti come port scan e trasferimenti di traffico particolarmente intensi.
    """
    if window_seconds <= 0:
        raise ValueError("La dimensione della finestra deve essere maggiore di zero.")

    if flows.empty:
        raise ValueError("Non sono presenti flow da aggregare.")

    flow_df = flows.copy()

    capture_start = flow_df["start_time"].min()
    capture_end = flow_df["start_time"].max()

    #assegno i flow alle finestre
    flow_df["window_id"] = ((flow_df["start_time"] - capture_start) // window_seconds).astype(int)

    #mi serve per capire quante finestre creare
    last_window_id = int((capture_end - capture_start) // window_seconds)

    windows = pd.DataFrame({"window_id": range(last_window_id + 1)})

    general_metrics = (flow_df.groupby("window_id").agg(
            new_flow_count=(
                "start_time",
                "size"
            ),
            distinct_destination_hosts=(
                "dst_ip",
                "nunique"
            ),
            average_packets_per_flow=(
                "packet_count",
                "mean"
            ),
            average_bytes_per_flow=(
                "byte_count",
                "mean"
            ),
            average_flow_duration=(
                "duration_seconds",
                "mean"
            )
        ).reset_index()
    )

    #per analizzare le porte uso solo TCP e UDP visto che ICMP non ha porte
    transport_flows = flow_df[flow_df["protocol"].isin(["TCP", "UDP"])].copy()

    if transport_flows.empty:
        port_metrics = pd.DataFrame(columns=["window_id","distinct_destination_ports","port_entropy"])

    else:
        #calcolo il numero di porte distinte di destinazione
        distinct_destination_ports = (transport_flows.groupby("window_id")["dst_port"]
            .nunique()
            .rename("distinct_destination_ports")
            .reset_index()
        )
        
        #caloclo entropia delle porte
        port_entropy = (transport_flows.groupby("window_id")["dst_port"]
            .apply(lambda ports: shannon_entropy(ports.tolist()))
            .rename("port_entropy")
            .reset_index()
        )

        #faccio il merge dei due DataFrame ottenuti sul campo Window_id
        port_metrics = (distinct_destination_ports.merge(port_entropy,on="window_id",how="outer"))

    #creo un unico dataFrame partendo da quello che contiene le finestre e aggiungendo: metriche generali e metriche sulle porte
    result = (windows.merge(
            general_metrics,
            on="window_id",
            how="left"
        )
        .merge(
            port_metrics,
            on="window_id",
            how="left"
        )
    )

    count_columns = [
        "new_flow_count",
        "distinct_destination_ports",
        "distinct_destination_hosts"
    ]

    average_columns = [
        "average_packets_per_flow",
        "average_bytes_per_flow",
        "average_flow_duration",
        "port_entropy"
    ]

    result[count_columns] = (result[count_columns].fillna(0).astype(int))
    result[average_columns] = (result[average_columns].fillna(0.0))
    result["window_start_seconds"] = (result["window_id"]* window_seconds)
    result["window_end_seconds"] = (result["window_start_seconds"]+ window_seconds)
    result["window_start_timestamp"] = (capture_start+ result["window_start_seconds"])
    result["window_start_datetime"] = (pd.to_datetime(result["window_start_timestamp"],unit="s"))

    ordered_columns = [
        "window_id",
        "window_start_seconds",
        "window_end_seconds",
        "window_start_datetime",
        "new_flow_count",
        "distinct_destination_ports",
        "distinct_destination_hosts",
        "port_entropy",
        "average_packets_per_flow",
        "average_bytes_per_flow",
        "average_flow_duration"
    ]

    return (result[ordered_columns].sort_values("window_id").reset_index(drop=True))