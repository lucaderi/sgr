import matplotlib.pyplot as plt

from analyzer.anomaly import METRIC_COLUMNS


# La metrica distinct_destination_hosts rimane nei CSV e nell'anomaly detection, ma non viene rappresentata graficamente perché non è significativa 
# nel caso di studio con un solo host target.
PLOT_METRICS = [metric for metric in METRIC_COLUMNS if metric != "distinct_destination_hosts"]

LABELS = {
    "new_flow_count": "Nuovi flow",
    "distinct_destination_ports": "Porte di destinazione distinte",
    "port_entropy": "Entropia delle porte di destinazione",
    "average_packets_per_flow": "Pacchetti medi per flow",
    "average_bytes_per_flow": "Byte medi per flow",
    "average_flow_duration": "Durata media dei flow"
}


Y_LABELS = {
    "new_flow_count": "Numero di nuovi flow",
    "distinct_destination_ports": "Numero di porte distinte",
    "port_entropy": "Entropia di Shannon",
    "average_packets_per_flow": "Pacchetti medi per flow",
    "average_bytes_per_flow": "Megabyte medi per flow",
    "average_flow_duration": "Durata media (secondi)"
}


def plot_metrics(anomaly_results, plots_dir):
    """
    Genera un grafico separato per ciascuna metrica selezionata.

    I punti già identificati come anomali dal modulo anomaly.py vengono evidenziati nei grafici.

    La metrica average_bytes_per_flow viene convertita da byte a megabyte esclusivamente per la visualizzazione.
    """
    if anomaly_results.empty:
        raise ValueError("Non sono presenti risultati da rappresentare.")

    if "window_start_seconds" not in anomaly_results.columns:
        raise ValueError("La colonna 'window_start_seconds' non è presente nel DataFrame.")

    plots_dir.mkdir(parents=True,exist_ok=True)
    #mi assicuro che il grafico venga disegnato in ordine temporale...anche se il DataFrame è gia ordinato
    plot_data = (anomaly_results.sort_values("window_start_seconds").copy())

    for metric in PLOT_METRICS:
        anomaly_column = f"{metric}_anomaly"

        if metric not in plot_data.columns:
            raise ValueError(f"La metrica '{metric}' non è presente nel DataFrame.")

        if anomaly_column not in plot_data.columns:
            raise ValueError(f"La colonna '{anomaly_column}' non è presente nel DataFrame.")

        if metric not in LABELS or metric not in Y_LABELS:
            raise ValueError(f"Non sono state definite le etichette per la metrica '{metric}'.")

        x_values = plot_data["window_start_seconds"]

        #Trasformo in MB solo per il grafico
        if metric == "average_bytes_per_flow":
            y_values = plot_data[metric] / (1024 * 1024)
        else:
            y_values = plot_data[metric]

        anomaly_mask = (plot_data[anomaly_column].astype(bool))

        fig, ax = plt.subplots(figsize=(12, 5.5))

        if metric == "new_flow_count":
            ax.bar(x_values,y_values,width=4,label=LABELS[metric])

        else:
            ax.plot(x_values,y_values,marker="o",linewidth=1.4,label=LABELS[metric])

        if anomaly_mask.any():
            ax.scatter(
                plot_data.loc[anomaly_mask,"window_start_seconds"],
                y_values.loc[anomaly_mask],
                marker="x",
                s=90,
                linewidths=2,
                label="Anomalia",
                zorder=3
            )

        ax.set_title(LABELS[metric],fontsize=15)
        ax.set_xlabel("Tempo dall'inizio (s)")
        ax.set_ylabel(Y_LABELS[metric])
        ax.grid(True,alpha=0.3)
        ax.legend()
        fig.tight_layout()
        output_path = (plots_dir/ f"{metric}.png")
        fig.savefig(output_path,dpi=300,bbox_inches="tight")
        plt.close(fig)