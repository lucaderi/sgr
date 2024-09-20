import numpy as np

def aggregate_by_ip(data):
    """
    The aggregate_by_ip function groups network flow data based on the source and destination IP addresses.
    It returns a dictionary of aggregated flows, where each key is an IP pair and each value is a list of flow dictionaries.

    params:
        - data: Pandas DataFrame from csv_read()

    return:
        - A dictionary of aggregated flows, where each key is an IP pair and each value is a list of flow dictionaries.
    """

    flows = data.to_dict("records")
    flows = sorted(flows, key=lambda x: (x["src_ip"], x["dst_ip"]))
    seen = []
    aggregated = {}
    for flow in flows:
        key = f"({flow['src_ip']} - {flow['dst_ip']})"
        reversed_key = f"({flow['dst_ip']} - {flow['src_ip']})"
        if key in seen:
            aggregated[key]["nFlows"] += 1
            aggregated[key]["pkts"] += flow["c_to_s_pkts"] + flow["s_to_c_pkts"]
            aggregated[key]["bytes"] += flow["s_to_c_bytes"] + flow["c_to_s_bytes"]
            aggregated[key]["syn"] += flow["syn"]
            aggregated[key]["ack"] += flow["ack"]
            aggregated[key]["rst"] += flow["rst"]
            aggregated[key]["fin"] += flow["fin"]
            aggregated[key]["psh"] += flow["psh"]
            aggregated[key]["urg"] += flow["urg"]
            aggregated[key]["syn/ack"] = (
                flow["syn"] / flow["ack"] if flow["ack"] != 0 else 0
            )
            aggregated[key]["bytes/pkts"] = (
                flow["s_to_c_bytes"] + flow["c_to_s_bytes"]
            ) / (flow["s_to_c_pkts"] + flow["c_to_s_pkts"])
            aggregated[key]["duration"].append(flow["duration"])
            aggregated[key]["iat_avg"].append(flow["iat_flow_avg"])
            aggregated[key]["goodputs_bytes"] += (
                flow["c_to_s_goodput_bytes"] + flow["s_to_c_goodput_bytes"]
            )
            aggregated[key]["goodputs_ratio"] += (
                flow["c_to_s_goodput_ratio"] + flow["s_to_c_goodput_ratio"]
            )
        elif reversed_key in seen:
            aggregated[reversed_key]["nFlows"] += 1
            aggregated[reversed_key]["pkts"] += (
                flow["s_to_c_pkts"] + flow["c_to_s_pkts"]
            )
            aggregated[reversed_key]["bytes"] += (
                flow["s_to_c_bytes"] + flow["c_to_s_bytes"]
            )
            aggregated[reversed_key]["syn"] += flow["syn"]
            aggregated[reversed_key]["ack"] += flow["ack"]
            aggregated[reversed_key]["rst"] += flow["rst"]
            aggregated[reversed_key]["fin"] += flow["fin"]
            aggregated[reversed_key]["psh"] += flow["psh"]
            aggregated[reversed_key]["urg"] += flow["urg"]
            aggregated[reversed_key]["syn/ack"] = (
                flow["syn"] / flow["ack"] if flow["ack"] != 0 else 0
            )
            aggregated[reversed_key]["bytes/pkts"] = (
                flow["s_to_c_bytes"] + flow["c_to_s_bytes"]
            ) / (flow["s_to_c_pkts"] + flow["c_to_s_pkts"])
            aggregated[reversed_key]["duration"].append(flow["duration"])
            aggregated[reversed_key]["iat_avg"].append(flow["iat_flow_avg"])
            aggregated[reversed_key]["goodputs_bytes"] += (
                flow["c_to_s_goodput_bytes"] + flow["s_to_c_goodput_bytes"]
            )
            aggregated[reversed_key]["goodputs_ratio"] += (
                flow["c_to_s_goodput_ratio"] + flow["s_to_c_goodput_ratio"]
            )
        else:
            seen.append(key)
            aggregated[key] = {
                "nFlows": 1,
                "pkts": flow["c_to_s_pkts"] + flow["s_to_c_pkts"],
                "bytes": flow["c_to_s_bytes"] + flow["s_to_c_bytes"],
                "syn": flow["syn"],
                "ack": flow["ack"],
                "rst": flow["rst"],
                "fin": flow["fin"],
                "psh": flow["psh"],
                "urg": flow["urg"],
                "syn/ack": flow["syn"] / flow["ack"] if flow["ack"] != 0 else 0,
                "bytes/pkts": (flow["c_to_s_bytes"] + flow["s_to_c_bytes"])
                / (flow["c_to_s_pkts"] + flow["s_to_c_pkts"]),
                "duration": [flow["duration"]],
                "iat_avg": [flow["iat_flow_avg"]],
                "goodputs_bytes": flow["c_to_s_goodput_bytes"]
                + flow["s_to_c_goodput_bytes"],
                "goodputs_ratio": flow["c_to_s_goodput_ratio"]
                + flow["s_to_c_goodput_ratio"],
            }
    aggregated = add_flag_ratio(aggregated, "syn")
    aggregated = add_flag_ratio(aggregated, "ack")
    aggregated = add_flag_ratio(aggregated, "rst")
    aggregated = add_flag_ratio(aggregated, "fin")
    aggregated = add_flag_ratio(aggregated, "psh")
    aggregated = add_flag_ratio(aggregated, "urg")
    return aggregated


def add_flag_ratio(aggregated_flows, flag):
    """
    Calculate the ratio of a specified flag (e.g., SYN, ACK) to the total number of packets for each aggregated flow.
    """
    for key, value in aggregated_flows.items():
        total_pkts = value["pkts"]
        flag_pkts = value[flag]
        flag_ratio = flag_pkts / total_pkts
        aggregated_flows[key][f"{flag}_ratio"] = flag_ratio
    return aggregated_flows


def aggregated_iqr_goodput_bytes(aggregated_flows):
    """
    The aggregated_iqr_goodput_bytes function calculates the interquartile range (IQR) for the goodput bytes of each aggregated flow and identifies outliers based on the IQR method.
    The function performs the following steps:
        - Calculates the IQR for the goodput bytes of each aggregated flow.
        - Identifies outliers based on the IQR values.
        - Returns a dictionary of outlier flows.

    params:
        - aggregated_flows: A dictionary of aggregated flows, where each key is an IP pair and each value is a dictionary containing flow statistics.

    return:
        - A dictionary of outlier flows, where each key is an IP pair and each value is a dictionary containing flow statistics.
    """

    # Calculate the IQR for the goodput bytes of each aggregated flow
    q1 = np.percentile(
        [value["goodputs_bytes"] for value in aggregated_flows.values()], 25
    )
    q3 = np.percentile(
        [value["goodputs_bytes"] for value in aggregated_flows.values()], 75
    )
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    # Identify outliers based on the IQR values
    outliers = {}
    for key, value in aggregated_flows.items():
        if (
            value["goodputs_bytes"] < lower_bound
            or value["goodputs_bytes"] > upper_bound
        ):
            outliers[key] = value

    return outliers


def aggregated_iqr_goodput_ratio(aggregated_flows):
    """
    The aggregated_iqr_goodput_ratio function calculates the interquartile range (IQR) for the goodput ratio of each aggregated flow and identifies outliers based on the IQR method.
    The function performs the following steps:
        - Calculates the IQR for the goodput ratio of each aggregated flow.
        - Identifies outliers based on the IQR values.
        - Returns a dictionary of outlier flows.

    params:
        - aggregated_flows: A dictionary of aggregated flows, where each key is an IP pair and each value is a dictionary containing flow statistics.

    return:
        - A dictionary of outlier flows, where each key is an IP pair and each value is a dictionary containing flow statistics.
    """

    # Calculate the IQR for the goodput ratio of each aggregated flow
    q1 = np.percentile(
        [value["goodputs_ratio"] for value in aggregated_flows.values()], 25
    )
    q3 = np.percentile(
        [value["goodputs_ratio"] for value in aggregated_flows.values()], 75
    )
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    # Identify outliers based on the IQR values
    outliers = {}
    for key, value in aggregated_flows.items():
        if (
            value["goodputs_ratio"] < lower_bound
            or value["goodputs_ratio"] > upper_bound
        ):
            outliers[key] = value

    return outliers


def aggregated_flag_pkts_ratio(aggregated_flows, flag="syn"):
    """
    The aggregated_flag_pkts_ratio function calculates the ratio of a specified flag (e.g., SYN, ACK) to the total number of packets for each aggregated flow.
    The function then identifies outliers based on the flag ratio values using the interquartile range (IQR) method.
    The function performs the following steps:
        - Calculates the flag ratio for each aggregated flow.
        - Identifies outliers based on the flag ratio values using the IQR method.
        - Returns a dictionary of outlier flows.

    params:
        - aggregated_flows: A dictionary of aggregated flows, where each key is an IP pair and each value is a dictionary containing flow statistics.
        - flag: The flag to be analyzed (e.g., "syn", "ack", "rst").

    return:
        - A dictionary of outlier flows, where each key is an IP pair and each value is a dictionary containing flow statistics.
    """

    # Calculate the IQR for the flag ratio of each aggregated flow
    q1 = np.percentile(
        [value[f"{flag}_ratio"] for value in aggregated_flows.values()], 25
    )
    q3 = np.percentile(
        [value[f"{flag}_ratio"] for value in aggregated_flows.values()], 75
    )
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    # Identify outliers based on the IQR values
    outliers = {}
    for key, value in aggregated_flows.items():
        if value[f"{flag}_ratio"] < lower_bound or value[f"{flag}_ratio"] > upper_bound:
            outliers[key] = value

    return outliers


def print_aggregated_flows(aggregated_flows):
    """
    The print_aggregated_flows function prints the aggregated flow data in a readable format.
    The function prints the IP pair, the number of flows, and the flow statistics (e.g., packets, bytes, flags).

    params:
        - aggregated_flows: A dictionary of aggregated flows, where each key is an IP pair and each value is a dictionary containing flow statistics.

    example:
    (A - B)
    nFlows: 2, pkts: 10, bytes: 600, syn: 11, ack: 9, rst: 0
    ########################################################
    (A - C)
    nFlows: 1, pkts: 10, bytes: 500, syn: 10, ack: 10, rst: 0
    ########################################################
    (A - D)
    nFlows: 1, pkts: 20, bytes: 1000, syn: 20, ack: 20, rst: 0
    ########################################################
    """
    for key, value in aggregated_flows.items():
        print(key)
        print(
            f"nFlows: {value['nFlows']}, pkts: {value['pkts']}, bytes: {value['bytes']}, syn: {value['syn']}, ack: {value['ack']}, rst: {value['rst']}"
        )
        print("########################################################")