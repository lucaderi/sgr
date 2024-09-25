#!/usr/bin/env python3
import pandas as pd
import os.path
import sys
import argparse
from itertools import combinations

# Custom imports
import features as ft
import graphs_utils as gu
import tfeatures as tf

TCP_FLAGS = ["fin", "syn", "rst", "psh", "ack", "urg"]

def main():
    args = parse_args()
    file = args.file
    save_dir = args.output
    if not os.path.exists(file):
        print("The file does not exist")
        sys.exit(1)
    elif not file.endswith(".csv"):
        print("The file must be a csv file")
        sys.exit(1)

    # now i have a valid CSV file to analyze
    print("File: ", file)
    proto = "MQTT"
    flags_to_use = args.flags
    # lower all the flags and check if they are valid
    flags_to_use = [flag.lower() for flag in flags_to_use]
    for flag in flags_to_use:
        if flag not in TCP_FLAGS:
            print(f"Flag {flag} is not valid")
            sys.exit(1)

    # Create a diurectory where to save all the graphs
    file_name = file.split("/")[-1].split(".")[0]
    save_dir = f"{save_dir}/{file_name}"

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    data = pd.read_csv(file, sep="|", low_memory=False)
    df = data[data["ndpi_proto"] == proto]
    gu.plot_all_graphs_generic(data, gu.generic_graphs_to_plot, title="Generic network information", directory=save_dir)

    dict = ft.aggregate_by_ip(df)
    generate_report(data)
    print_outliers(dict, flags_to_use, save_dir=save_dir)

    sys.exit(0)



def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(
        description="An anomaly detection system for IoT networks"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="The CSV file to analyze (must be ndpiReader format)",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="The output directory for the graphs",
        required=False,
        default="imgs",
    )
    parser.add_argument(
        '-F',
        '--flags',
        nargs='+',
        default=['rst'],
        help='[rst, ack, syn, psh, urg] Flags to use for the analysis',
        required=False
    )
    args = parser.parse_args()
    return args


def generate_report(data):
    """
    Generate a report with the following information:
    - Total number of flows
    - Traffic distribution by protocol
    - Top talkers
    - Total packets
    - Total bytes
    - Total goodput bytes
    - Average flow duration
    - Flow duration distribution
    - Packet length distribution
    - Inter-arrival time statistics
    params:
        data (pd.DataFrame): The data to generate the report from
    """
    print("\nReport:\n-----------------------------------------------------------------")
    # Total flows
    total = tf.total_flows(data)
    print(f"Total number of flows: {total}\n-----------------------------------------------------------------")

    # Traffic distribution by protocol
    protocol_dist, protocol_percentages = tf.traffic_distribution_by_protocol(data)
    print("Traffic distribution by protocol:")
    for proto, bytes_sent in protocol_dist.items():
        print(f"{proto}: {bytes_sent} bytes ({protocol_percentages[proto]:.2f}%)")
    print("-----------------------------------------------------------------")

    # Top talkers
    top_talkers_result = tf.top_talkers(data, n=5)
    print("Top 5 talkers (src_ip) and the volume of bytes sent:")
    for ip, bytes_sent in top_talkers_result.items():
        print(f"{ip}: {bytes_sent} bytes")
    print("-----------------------------------------------------------------")

    # Total packets
    s_to_c_tot_pkts, c_to_s_tot_pkts, tot_pkts = tf.tot_pkts(data)
    print(f"Total packets sent from client to server: {s_to_c_tot_pkts}")
    print(f"Total packets received from server to client: {c_to_s_tot_pkts}")
    print(f"Total packets overall: {tot_pkts}\n-----------------------------------------------------------------")

    # Total bytes
    s_to_c_tot, c_to_s_tot, tot_bytes = tf.tot_bytes(data)
    print(f"Total bytes sent from client to server: {s_to_c_tot}")
    print(f"Total bytes received from server to client: {c_to_s_tot}")
    print(f"Total bytes overall: {tot_bytes}\n-----------------------------------------------------------------")

    # Total goodput bytes
    s_to_c_tot_goodput, c_to_s_tot_goodput, tot_goodput_bytes = tf.tot_goodput_bytes(data)
    print(f"Total goodput bytes sent from client to server: {s_to_c_tot_goodput}")
    print(f"Total goodput bytes received from server to client: {c_to_s_tot_goodput}")
    print(f"Total goodput bytes overall: {tot_goodput_bytes}\n-----------------------------------------------------------------")

    # Average flow duration
    avg_duration = tf.avg_flow_duration(data)
    print(f"Average flow duration: {avg_duration:.2f} seconds\n-----------------------------------------------------------------")

    # Flow duration distribution
    duration_hist, duration_bins = tf.flow_duration_distribution(data)
    print("Flow duration distribution:")
    for i in range(len(duration_hist)):
        print(f"{duration_bins[i]:.0f} - {duration_bins[i+1]:.0f} seconds: {duration_hist[i]} flows")
    print("-----------------------------------------------------------------")

    # Packet length distribution
    pktlen_hist, pktlen_bins, pktlen_percentages = tf.packet_len_distribution(data)
    print("Packet length distribution:")
    for i in range(len(pktlen_hist)):
        print(f"{pktlen_bins[i]:.0f} - {pktlen_bins[i+1]:.0f} bytes: {pktlen_hist[i]} packets ({pktlen_percentages[i]:.2f}%)")
    print("-----------------------------------------------------------------")

    # Inter-arrival time statistics
    iat_min, iat_max, iat_avg = tf.iat_statistics(data)
    print(f"Minimum inter-arrival time: {iat_min:.2f} milliseconds")
    print(f"Maximum inter-arrival time: {iat_max:.2f} milliseconds")
    print(f"Average inter-arrival time: {iat_avg:.2f} milliseconds")
    print("-----------------------------------------------------------------")



def jaccard_similarity(set1, set2):
    """
    Calculate the Jaccard similarity between two sets.

    params:
        set1 (set): First set of elements.
        set2 (set): Second set of elements.

    return:
        float: Jaccard similarity between the two sets.
    """
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union != 0 else 0

def print_outliers(aggregated_flows, flags, save_dir="imgs", jaccard_threshold=0.75):
    """
    This function uses various outlier detection methods to identify and print potential outliers
    in the aggregated flows data. It combines outlier detection based on IQR for goodput bytes,
    goodput ratio, and flag packet ratio, and calculates Jaccard similarity for detected outliers.

    params:
        aggregated_flows (dict): A dictionary of aggregated flows where each key is an IP pair and each
        value is a dictionary containing flow statistics.
    """
    print("\nAnomalies section:\n-----------------------------------------------------------------")
    # Detect outliers based on IQR of goodput bytes
    goodput_bytes_outliers = ft.aggregated_iqr_goodput_bytes(aggregated_flows)
    print("Anomalies based on IQR of goodput bytes:")
    if goodput_bytes_outliers:
        for key, value in goodput_bytes_outliers.items():
            print(f"IP Pair: {key}, Goodput Bytes: {value['goodputs_bytes']}")
    else:
        print("No anomalies detected based on goodput bytes.")
    print("-----------------------------------------------------------------")
    
    # Detect outliers based on IQR of goodput ratio
    goodput_ratio_outliers = ft.aggregated_iqr_goodput_ratio(aggregated_flows)
    print("Anomalies based on IQR of goodput ratio:")
    if goodput_ratio_outliers:
        for key, value in goodput_ratio_outliers.items():
            print(f"IP Pair: {key}, Goodput Ratio: {value['goodputs_ratio']:.2f}")
    else:
        print("No anomalies detected based on goodput ratio.")
    print("-----------------------------------------------------------------")
    
    # Detect outliers based on IQR of flag packet ratio
    flag_outliers = {}
    for flag in flags:
        flag_outliers[flag] = ft.aggregated_flag_pkts_ratio(aggregated_flows, flag=flag)
        print(f"Anomalies based on IQR of {flag} packet ratio:")
        if flag_outliers[flag]:
            for key, value in flag_outliers[flag].items():
                print(f"IP Pair: {key}, {flag} Packet Ratio: {value[f'{flag}_ratio']:.2f}")
        else:
            print(f"No anomalies detected based on {flag} packet ratio.")
        print("-----------------------------------------------------------------")
    
    # Combine all detected outliers
    all_outliers = set(goodput_bytes_outliers.keys()).union(
        set(goodput_ratio_outliers.keys())
    )
    for flag in flags:
        all_outliers = all_outliers.union(flag_outliers[flag].keys())
  
    # merge all outliers dictionaries into one, mantaining the key as the IP pair
    all_outliers_dict = {}
    for outlier in all_outliers:
        all_outliers_dict[outlier] = {}
        for flag in flags:
            all_outliers_dict[outlier][flag] = flag_outliers[flag].get(outlier, None)
        all_outliers_dict[outlier]["goodput_bytes"] = goodput_bytes_outliers.get(outlier, None)
        all_outliers_dict[outlier]["goodput_ratio"] = goodput_ratio_outliers.get(outlier, None)
            
    # Print Jaccard similarity between sets of outliers
    print("Jaccard Similarity between sets of anomalies:")
    outlier_sets = {
        "Goodput Bytes": set(goodput_bytes_outliers.keys()),
        "Goodput Ratio": set(goodput_ratio_outliers.keys()),
    }
    for flag in flags:
        outlier_sets[f"{flag} Ratio"] = set(flag_outliers[flag].keys())
    
    flag_outliers_dict = {}
    for flag_set in outlier_sets:
        for outlier in outlier_sets[flag_set]:
            flag_outliers_dict[outlier] = aggregated_flows[outlier]

    for (label1, set1), (label2, set2) in combinations(outlier_sets.items(), 2):
        similarity = jaccard_similarity(set1, set2)
        print(f"Jaccard Similarity between {label1} and {label2}: {similarity:.2f}")

    outlier_sets = {"Goodput Bytes": set(goodput_bytes_outliers.keys()),"Goodput Ratio": set(goodput_ratio_outliers.keys()),}
    for flag in flags:
        outlier_sets[f"{flag} Ratio"] = set(flag_outliers[flag].keys())
    print("-----------------------------------------------------------------")
    print(f"Anomalies with jaccard similarity >= {jaccard_threshold}:")
    detected_outliers = set()
    
    for (label1, set1), (label2, set2) in combinations(outlier_sets.items(), 2):
        similarity = jaccard_similarity(set1, set2)
        if similarity >= jaccard_threshold:
            print(f"Jaccard Similarity between {label1} and {label2}: {similarity:.2f}")
            detected_outliers = detected_outliers.union(set1.intersection(set2))
    print("-----------------------------------------------------------------")
    if detected_outliers:
        print("#################################################################")
        print("[WARNING] Potential anomalies detected!")
        print("#################################################################")
        print("Common anomalies detected:")
        for outlier in detected_outliers:
            print(f"IP Pair: {outlier}")
    else:
        print("No anomalies detectet with Jaccard similarity.")


    detected_outliers_dict = {}
    for outlier in detected_outliers:
        detected_outliers_dict[outlier] = aggregated_flows[outlier]
    
    # Get all the dected outliers in a dictionary using the keys from detected_outliers set
    gu.plot_all_graphs_analysis(aggregated_flows, detected_outliers_dict, gu.analysis_graphs_to_plot, title="Network analysis information", directory=save_dir)

if __name__ == "__main__":
    main()