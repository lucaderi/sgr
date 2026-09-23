import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP

def get_transport_information(packet):
    """
    Estrae le informazioni necessarie per identificare il protocollo di livello trasporto.

    Per TCP e UDP restituisce le porte sorgente e destinazione.

    ICMP non utilizza porte: Le rappresento convenzionalmente con il valore 0.

    Se il pacchetto IP non contiene TCP, UDP o ICMP, la funzione restituisce None.
    """
    if TCP in packet:
        return (
            int(packet[TCP].sport),
            int(packet[TCP].dport),
            "TCP"
        )

    if UDP in packet:
        return (
            int(packet[UDP].sport),
            int(packet[UDP].dport),
            "UDP"
        )

    if ICMP in packet:
        return 0, 0, "ICMP"

    return None


def create_flow(src_ip,dst_ip,src_port,dst_port,protocol,timestamp):
    """
    Crea un nuovo record di flow a partire dal primo pacchetto osservato.
    """
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "start_time": timestamp,
        "end_time": timestamp,
        "packet_count": 0,
        "byte_count": 0
    }


def close_flow(flow, termination_reason):
    """
    Conclude un flow calcolandone la durata e registrando il motivo della chiusura.
    """
    flow["duration_seconds"] = max(0.0,flow["end_time"] - flow["start_time"])

    flow["termination_reason"] = termination_reason

    return flow


def build_flows(packets,inactive_timeout=15,active_timeout=1800):
    """
    Ricostruisce flow IPv4 unidirezionali.

    Ogni flow viene identificato mediante la classica 5-tupla:

        - indirizzo IP sorgente;
        - indirizzo IP destinazione;
        - porta sorgente;
        - porta destinazione;
        - protocollo.

    Vengono analizzati solamente pacchetti IPv4 contenenti TCP, UDP o ICMP.

    Un flow viene chiuso in tre possibili situazioni:

    1. Inactive timeout: non vengono osservati pacchetti appartenenti al flow per almeno 15 secondi.
    2. Active timeout: la durata complessiva del flow raggiunge i 30 minuti, anche se il traffico continua a essere attivo.
    3. Fine della cattura: il file PCAP termina prima della scadenza dei timeout.

    I flow sono unidirezionali. Pertanto, i pacchetti nelle due direzioni della stessa comunicazione producono due flow distinti.
    """
    if inactive_timeout <= 0:
        raise ValueError("L'inactive timeout deve essere maggiore di zero.")

    if active_timeout <= 0:
        raise ValueError("L'active timeout deve essere maggiore di zero.")

    active_flows = {}
    completed_flows = []

    sorted_packets = sorted(packets,key=lambda packet: float(packet.time))

    for packet in sorted_packets:
        if IP not in packet:
            continue

        transport_information = get_transport_information(packet)

        if transport_information is None:
            continue

        src_port, dst_port, protocol = transport_information

        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)

        timestamp = float(packet.time)
        packet_size = len(packet)

        flow_key = (src_ip,dst_ip,src_port,dst_port,protocol)

        if flow_key in active_flows:
            current_flow = active_flows[flow_key]

            inactive_time = (timestamp - current_flow["end_time"])

            active_time = (timestamp - current_flow["start_time"])

            if inactive_time >= inactive_timeout:
                completed_flows.append(close_flow(current_flow,"inactive_timeout"))

                active_flows[flow_key] = create_flow(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    timestamp
                )

            elif active_time >= active_timeout:
                completed_flows.append(close_flow(current_flow,"active_timeout"))

                active_flows[flow_key] = create_flow(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    timestamp
                )

        else:
            active_flows[flow_key] = create_flow(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                timestamp
            )

        current_flow = active_flows[flow_key]

        current_flow["end_time"] = timestamp
        current_flow["packet_count"] += 1
        current_flow["byte_count"] += packet_size

    for flow in active_flows.values():
        completed_flows.append(close_flow(flow,"end_of_capture"))

    columns = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "start_time",
        "end_time",
        "duration_seconds",
        "packet_count",
        "byte_count",
        "termination_reason"
    ]

    return pd.DataFrame(completed_flows,columns=columns)