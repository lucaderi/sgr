import csv
import logging
from pathlib import Path
 
from snmp_monitor.models import InterfaceMetric
 
logger = logging.getLogger(__name__)

# Indica al csv quali colonne scrivere
FIELDNAMES = [
    "timestamp",
    "agent",
    "if_index",
    "if_name",
    "if_status",
    "in_octets",
    "out_octets",
    "in_errors",
    "out_errors",
    "in_mbps",
    "out_mbps",
]

def metric_to_dict(metric: InterfaceMetric) -> dict:
    """
    Converte una InterfaceMetric in un dizionario utilizzabile dal CSV
    """
    
    # Se in_mbps e out_mbps sono null al primo ciclo viene scritta una stringa vuota
    return {
        "timestamp": metric.timestamp.isoformat(),
        "agent": metric.agent,
        "if_index": metric.if_index,
        "if_name": metric.if_name,
        "if_status": metric.if_status,
        "in_octets": metric.in_octets,
        "out_octets": metric.out_octets,
        "in_errors": metric.in_errors,
        "out_errors": metric.out_errors,
        "in_mbps": "" if metric.in_mbps is None else metric.in_mbps,
        "out_mbps": "" if metric.out_mbps is None else metric.out_mbps,
    }
    
def write_csv(metrics: list[InterfaceMetric], path: str) -> None:
    """
    Scrive la lista di InterfaceMetric nel csv
    """
    
    # Se metrics è vuota non scrive nulla
    if not metrics:
        return 
    
    file_path = Path(path)
    file_exist = file_path.exists() and file_path.stat().st_size > 0
    
    # Il file viene aperto in modalità append. Quando vengono ci sono nuovi dati, vengono aggiunti a quelli esistenti.
    try:
        with file_path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, FIELDNAMES)
            
            # Se il file non esiste o è vuoto viene creata la riga di intestazione dei primi dati
            if not file_exist:
                writer.writeheader()
                
            for metric in metrics:
                writer.writerow(metric_to_dict(metric))
            
    except OSError as exc:
        logger.error("Impossibile scrivere su %s: %s", path, exc)
        raise 
    
    logger.debug("Scritte %d righe su %s", len(metrics), path)   