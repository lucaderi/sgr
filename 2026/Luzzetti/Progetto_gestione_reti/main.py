import argparse
import sys
from pathlib import Path

from analyzer.anomaly import detect_anomalies
from analyzer.flow_builder import build_flows
from analyzer.metrics import build_window_metrics
from analyzer.pcap_parser import read_packets
from analyzer.plotting import plot_metrics

#Definizione degli argomenti di input
def parse_arguments():
    parser = argparse.ArgumentParser(
        description=("Analizza un file PCAP, ricostruisce i flow, calcola metriche temporali e individua anomalie tramite z-score.")
    )
    parser.add_argument(
        "pcap_file",
        type=Path,
        help="Percorso del file PCAP da analizzare.",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Dimensione della finestra temporale in secondi. Default: 5.",
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=3.0,
        help="Soglia assoluta dello z-score. Default: 3.0s",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory in cui salvare CSV e grafici. Default: output.",
    )
    return parser.parse_args()

#Validazione degli argomenti di input
def validate_arguments(args):
    if not args.pcap_file.exists():
        raise FileNotFoundError(f"File PCAP non trovato: {args.pcap_file}")

    if not args.pcap_file.is_file():
        raise ValueError(f"Il percorso non indica un file: {args.pcap_file}")

    if args.window <= 0:
        raise ValueError("La finestra temporale deve essere maggiore di zero.")

    if args.z_threshold <= 0:
        raise ValueError("La soglia z-score deve essere maggiore di zero.")

#Preparo la directory di output
def prepare_output_directories(output_dir):
    csv_dir = output_dir / "csv"
    plots_dir = output_dir / "plots"

    #parents=True crea anche la directory padre se non esiste, Exist_ok=True non fa nulla se la directory esiste gia
    csv_dir.mkdir(parents=True, exist_ok=True)
    plots_dir.mkdir(parents=True, exist_ok=True)

    return csv_dir, plots_dir

#Definisco il main che restituisce un output intero come codice. 0->esecuzione corretta, 1->errore previsto, 2->errore inatteso
def main():
    args = parse_arguments()

    try:
        validate_arguments(args)
        csv_dir, plots_dir = prepare_output_directories(args.output_dir)

        print(f"[1/5] Lettura del PCAP: {args.pcap_file}")
        packets = read_packets(args.pcap_file)
        print(f"      Pacchetti letti: {len(packets)}")

        print("[2/5] Ricostruzione dei flow IP")
        flows = build_flows(packets)
        flows.to_csv(csv_dir / "flows.csv",index=False)
        print(f"      Flow ricostruiti: {len(flows)}")

        print(f"[3/5] Aggregazione in finestre temporali da {args.window} secondi")
        metrics = build_window_metrics(flows, args.window)
        metrics.to_csv(csv_dir / "window_metrics.csv", index=False)

        print(f"[4/5] Rilevazione anomalie con soglia z = {args.z_threshold}")
        anomalies = detect_anomalies(metrics, args.z_threshold, baseline_windows=6)
        anomalies.to_csv(csv_dir / "anomalies.csv", index=False)

        print("[5/5] Generazione dei grafici")
        plot_metrics(anomalies, plots_dir)

        anomaly_rows = int(anomalies["is_anomaly"].sum())
        print()
        print("Analisi completata.")
        print(f"Finestre analizzate: {len(metrics)}")
        print(f"Segnalazioni di anomalia: {anomaly_rows}")
        print(f"CSV salvati in: {csv_dir.resolve()}")
        print(f"Grafici salvati in: {plots_dir.resolve()}")

        return 0

    except (FileNotFoundError, ValueError) as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Errore inatteso: {exc}", file=sys.stderr)
        return 2

#metto questo perchè almeno eseguo il main solamente quando il file viene lanciato direttamente
if __name__ == "__main__":
    #SystemExit utilizza il valore restituito da main() come codice di uscita del programma.
    raise SystemExit(main())
