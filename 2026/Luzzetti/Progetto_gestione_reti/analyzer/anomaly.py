import numpy as np
import pandas as pd


METRIC_COLUMNS = [
    "new_flow_count",
    "distinct_destination_ports",
    "distinct_destination_hosts",
    "port_entropy",
    "average_packets_per_flow",
    "average_bytes_per_flow",
    "average_flow_duration"
]


def calculate_z_score(values, mean, standard_deviation):
    """
    Calcola lo z-score di una serie di valori rispetto alla media e alla deviazione standard della baseline.

    Se la deviazione standard è zero o non è valida, restituisce una serie di z-score pari a zero.
    """

    #Faccio questo controllo perchè se tutti i valori della baseline sono uguali e la deviazione standard è zero e non posso dividere per zero
    if standard_deviation == 0 or np.isnan(standard_deviation):
        #creo una serie di z-score pari a zero, con lo stesso indice della colonna originale.
        return pd.Series(0.0,index=values.index)

    return (values - mean) / standard_deviation


def detect_anomalies(metrics,threshold=3.0,baseline_windows=None):
    """
    Funzione per individuare anomalie nelle metriche aggregate per finestra temporale.

    La media e la deviazione standard possono essere calcolate:

    - su tutte le finestre, se baseline_windows è None;
    - sulle prime baseline_windows finestre, se il parametro viene specificato.

    Per ogni metrica vengono aggiunte due colonne:

    - <metrica>_zscore;
    - <metrica>_anomaly.

    Vengono considerati anomali solamente i picchi positivi, cioè i valori con z-score superiore alla soglia.

    Vengono inoltre aggiunte:

    - anomaly_score: numero di metriche anomale nella finestra;
    - is_anomaly: True se almeno due metriche risultano contemporaneamente anomale.
    """

    if threshold <= 0:
        raise ValueError("La soglia z-score deve essere maggiore di zero.")

    if metrics.empty:
        raise ValueError("Non sono presenti metriche da analizzare.")

    if baseline_windows is not None:
        if baseline_windows <= 0:
            raise ValueError("Il numero di finestre di baseline deve essere maggiore di zero.")

        if baseline_windows > len(metrics):
            raise ValueError("Il numero di finestre di baseline non può essere maggiore del numero totale di finestre.")

    missing_columns = [metric for metric in METRIC_COLUMNS if metric not in metrics.columns]

    if missing_columns:
        raise ValueError("Nel DataFrame mancano le seguenti metriche: "+ ", ".join(missing_columns))

    result = metrics.copy()

    if baseline_windows is None:
        baseline = result
    else:
        baseline = result.head(baseline_windows)

    anomaly_columns = []

    for metric in METRIC_COLUMNS:
        baseline_mean = baseline[metric].mean()

        baseline_standard_deviation = (baseline[metric].std(ddof=0))

        zscore_column = f"{metric}_zscore"
        anomaly_column = f"{metric}_anomaly"

        result[zscore_column] = calculate_z_score(result[metric],baseline_mean,baseline_standard_deviation)

        result[anomaly_column] = (result[zscore_column] > threshold)

        anomaly_columns.append(anomaly_column)

    result["anomaly_score"] = (result[anomaly_columns].sum(axis=1).astype(int))

    result["is_anomaly"] = (result["anomaly_score"] >= 2)

    return result