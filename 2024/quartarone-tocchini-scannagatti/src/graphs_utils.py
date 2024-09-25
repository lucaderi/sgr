import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math

generic_graphs_to_plot = [
    lambda data, ax: plot_protocol_distribution(data, ax),
    lambda data, ax: plot_top_ip_occurences(data, ax, ax),
    lambda data, ax: plot_bytes_traffic(data, ax),
    lambda data, ax: plot_goodput_bytes_traffic(data, ax),
    lambda data, ax: plot_packet_size_distribution(data, ax),
]

analysis_graphs_to_plot = [
    lambda af, ax, out: plot_aggregated_iqr_goodput_bytes(af, ax, out),
    lambda af, ax, out: plot_aggregated_iqr_goodput_ratio(af, ax, out),
    lambda af, ax, out: plot_outliers_pie_chart(af, ax, out),
]


def plot_protocol_distribution(data, ax):
    """
    Creates a pie chart showing the distribution of protocols based on the total bytes exchanged.

    Parameters:
    - data (pd.DataFrame): DataFrame with columns 'ndpi_proto' and 'total_bytes'.
    - ax (matplotlib.axes.Axes): Axis on which to draw the pie chart.
    """
    c_to_s_bytes = data["c_to_s_bytes"].dropna()
    s_to_c_bytes = data["s_to_c_bytes"].dropna()

    # Calculate the total bytes exchanged for each protocol
    total_bytes = np.array(c_to_s_bytes) + np.array(s_to_c_bytes)

    # Add the total bytes to the DataFrame
    data["total_bytes"] = total_bytes
    protocol_traffic = data.groupby("ndpi_proto")["total_bytes"].sum()
    threshold = 0.05

    # Filter out protocols with less than 5% of the total traffic
    mask = protocol_traffic / protocol_traffic.sum() > threshold
    protocol_traffic = protocol_traffic[mask]

    # Plot the pie chart
    ax.pie(
        protocol_traffic,
        labels=protocol_traffic.index,
        autopct="%1.1f%%",
        startangle=90,
    )
    ax.axis("equal")
    ax.set_title("Protocol Distribution")


def plot_top_ip_occurences(data, ax1, ax2, top=10, bar_width=0.35):
    """
    Creates a bar chart where, for each IP, the number of occurrences as source (in blue) and destination (in orange) are shown side by side.

    Parameters:
    - data (pd.DataFrame): DataFrame with columns 'src_ip' and 'dst_ip'.
    - ax1 (matplotlib.axes.Axes): Axis on which to draw the chart for source IPs.
    - ax2 (matplotlib.axes.Axes): Axis on which to draw the chart for destination IPs.
    - top (int): Number of top IPs to show.
    - bar_width (float): Width of the bars. Default is 0.35.
    """
    src_ip_counts = data["src_ip"].value_counts()
    dst_ip_counts = data["dst_ip"].value_counts()

    top_src_ips = src_ip_counts.head(top)
    top_dst_ips = dst_ip_counts.head(top)

    top = min(top, len(top_src_ips), len(top_dst_ips))

    indices = np.arange(top)

    # Plotting for source IPs
    ax1.bar(indices, top_src_ips.values, bar_width, color="skyblue", label="Source IP")
    ax1.set_xlabel("Source IP")
    ax1.set_ylabel("Count")
    ax1.set_title(f"Top {top} IP Occurrences")
    ax1.set_xticks(indices)
    ax1.set_xticklabels(top_src_ips.index, rotation=45)
    ax1.legend()

    # Plotting for destination IPs with offset
    ax2.bar(
        indices + bar_width,
        top_dst_ips.values,
        bar_width,
        color="orange",
        label="Destination IP",
    )
    ax2.set_xlabel("Destination IP")
    ax2.set_ylabel("Count")
    ax2.set_xticks(indices + bar_width / 2)
    ax2.set_xticklabels(top_dst_ips.index, rotation=45)
    ax2.legend()


def plot_bytes_traffic(data, ax, top=10, bar_width=0.35):
    """
    Creates a bar chart where, for each IP, the total bytes sent (in orange) and received (in blue) are shown side by side.

    Parameters:
    - data (pd.DataFrame): DataFrame with columns 'src_ip', 'c_to_s_bytes', and 's_to_c_bytes'.
    - ax (matplotlib.axes.Axes): Axis on which to draw the chart.
    - top (int): Number of top IPs to show.
    - bar_width (float): Width of the bars. Default is 0.35.
    """
    # Group by IP and sum the bytes sent and received
    ip_traffic = data.groupby("src_ip")[["c_to_s_bytes", "s_to_c_bytes"]].sum()
    ip_traffic["total_bytes"] = ip_traffic["c_to_s_bytes"] + ip_traffic["s_to_c_bytes"]

    # Select the top IPs with the most total bytes
    top_ip_traffic = ip_traffic.sort_values("total_bytes", ascending=False).head(top)

    top = min(top, len(top_ip_traffic))

    # Creation of positions for the bars
    indices = np.arange(top)

    # Plot for the bytes sent (client-to-server)
    ax.bar(
        indices,
        top_ip_traffic["c_to_s_bytes"],
        bar_width,
        color="skyblue",
        label="Client to Server Bytes",
    )

    # Plot for the bytes received (server-to-client) with offset
    ax.bar(
        indices + bar_width,
        top_ip_traffic["s_to_c_bytes"],
        bar_width,
        color="orange",
        label="Server to Client Bytes",
    )

    ax.set_xlabel("Source IP")
    ax.set_ylabel("Total Bytes")
    ax.set_title(f"Top {top} IP Traffic")
    ax.set_xticks(indices + bar_width / 2)
    ax.set_xticklabels(top_ip_traffic.index, rotation=45)
    ax.legend()


def plot_goodput_bytes_traffic(data, ax, top=10, bar_width=0.35):
    """
    Creates a bar chart where, for each IP, the total goodput bytes sent (in orange) and received (in blue) are shown side by side.

    Parameters:
    - data (pd.DataFrame): DataFrame with columns 'src_ip', 'c_to_s_goodput_bytes', and 's_to_c_goodput_bytes'.
    - ax (matplotlib.axes.Axes): Axis on which to draw the chart.
    - top (int): Number of top IPs to show.
    - bar_width (float): Width of the bars. Default is 0.35.

    """
    # Group by IP and sum the goodput bytes sent and received
    ip_traffic = data.groupby("src_ip")[
        ["c_to_s_goodput_bytes", "s_to_c_goodput_bytes"]
    ].sum()
    ip_traffic["total_goodput_bytes"] = (
        ip_traffic["c_to_s_goodput_bytes"] + ip_traffic["s_to_c_goodput_bytes"]
    )

    top = min(top, len(ip_traffic))

    # Select the top IPs with the most total goodput bytes
    top_ip_traffic = ip_traffic.sort_values(
        "total_goodput_bytes", ascending=False
    ).head(top)


    indices = np.arange(top)

    # Plot for the bytes di goodput sent (client-to-server)
    ax.bar(
        indices,
        top_ip_traffic["c_to_s_goodput_bytes"],
        bar_width,
        color="skyblue",
        label="Client to Server Goodput Bytes",
    )

    # Plot for the bytes di goodput received (server-to-client) with offset
    ax.bar(
        indices + bar_width,
        top_ip_traffic["s_to_c_goodput_bytes"],
        bar_width,
        color="orange",
        label="Server to Client Goodput Bytes",
    )

    ax.set_xlabel("Source IP")
    ax.set_ylabel("Total Goodput Bytes")
    ax.set_title(f"Top {top} IP Goodput Traffic")
    ax.set_xticks(indices + bar_width / 2)
    ax.set_xticklabels(top_ip_traffic.index, rotation=45)
    ax.legend()


def plot_packet_size_distribution(data, ax):
    """
    Creates an histogram showing the distribution of packet sizes.

    Parameters:
    - data (pd.DataFrame): DataFrame with columns 'pktlen_c_to_s_min', 'pktlen_c_to_s_avg', 'pktlen_c_to_s_max', 'pktlen_s_to_c_min', 'pktlen_s_to_c_avg', and 'pktlen_s_to_c_max'.
    - ax (matplotlib.axes.Axes): Axis on which to draw the histogram.
    """
    # Concat all the packet sizes columns
    packet_sizes = pd.concat(
        [
            data["pktlen_c_to_s_min"],
            data["pktlen_c_to_s_avg"],
            data["pktlen_c_to_s_max"],
            data["pktlen_s_to_c_min"],
            data["pktlen_s_to_c_avg"],
            data["pktlen_s_to_c_max"],
        ],
        ignore_index=True,
    )

    packet_sizes = packet_sizes.dropna()
    ax.hist(packet_sizes, bins=50, density=True, alpha=0.6, color="r")
    ax.set_title("Packet Size Distribution")
    ax.set_xlabel("Packet Size")
    ax.set_ylabel("Density")


def plot_all_graphs_generic(data, graphs_to_plot, title, directory="imgs"):

    # Calculate the number of rows and columns needed to display all the graphs
    num_graphs = len(graphs_to_plot)
    num_cols = 2
    num_rows = math.ceil(num_graphs / num_cols)

    fig, axs = plt.subplots(num_rows, num_cols, figsize=(25, 5 * num_rows))
    fig.suptitle(f"{title}", fontsize=24, fontweight="bold")

    for i, plot_fn in enumerate(graphs_to_plot):
        row = i // num_cols
        col = i % num_cols
        ax = axs[row, col] if num_rows > 1 else axs[col]
        plot_fn(data, ax)

    for i in range(num_graphs, num_rows * num_cols):
        row = i // num_cols
        col = i % num_cols
        axs[row, col].axis("off")

    plt.tight_layout()
    plt.savefig(f"{directory}/graphs_generic.png")
    plt.close()


def plot_all_graphs_analysis(
    aggregated_flows, outliers, graphs_to_plot, title, directory="imgs"
):
    # Calculate the number of rows and columns needed to display all the graphs
    num_graphs = len(graphs_to_plot)
    num_cols = 2
    num_rows = math.ceil(num_graphs / num_cols)

    fig, axs = plt.subplots(num_rows, num_cols, figsize=(25, 5 * num_rows))

    fig.suptitle(f"{title}", fontsize=24, fontweight="bold")

    for i, plot_fn in enumerate(graphs_to_plot):
        row = i // num_cols
        col = i % num_cols
        ax = axs[row, col] if num_rows > 1 else axs[col]
        plot_fn(aggregated_flows, ax, outliers)

    for i in range(num_graphs, num_rows * num_cols):
        row = i // num_cols
        col = i % num_cols
        axs[row, col].axis("off")

    plt.tight_layout()
    plt.savefig(f"{directory}/graphs_analysis.png")
    plt.close()


def plot_aggregated_iqr_goodput_bytes(aggregated_flows, ax, outliers):
    goodput_bytes = [value["goodputs_bytes"] for value in aggregated_flows.values()]

    outlier_indices = []
    outlier_goodput_bytes = []
    outlier_labels = []
    for idx, (ip_pair, value) in enumerate(aggregated_flows.items()):
        if ip_pair in outliers:
            outlier_indices.append(idx)
            outlier_goodput_bytes.append(value["goodputs_bytes"])
            outlier_labels.append(f"{ip_pair}")

    ax.scatter(
        range(len(goodput_bytes)),
        goodput_bytes,
        label="Goodput Bytes",
        alpha=0.6,
        color="b",
    )
    ax.scatter(outlier_indices, outlier_goodput_bytes, color="r", label="Outliers")

    for idx, label in zip(outlier_indices, outlier_labels):
        ax.annotate(
            label,
            (idx, goodput_bytes[idx]),
            textcoords="offset points",
            xytext=(0, 10),
            ha="center",
            rotation=20,
            fontsize=6,
            arrowprops=dict(arrowstyle="-", color="gray"),
        )

    ax.set_title("Scatter Plot of Goodput Bytes with Outliers")
    ax.set_xlabel("Flow Index")
    ax.set_ylabel("Goodput Bytes")
    ax.legend()


def plot_aggregated_iqr_goodput_ratio(aggregated_flows, ax, outliers):
    goodput_ratios = [value["goodputs_ratio"] for value in aggregated_flows.values()]

    outlier_indices = []
    outlier_goodput_ratios = []
    outlier_labels = []
    for idx, (ip_pair, value) in enumerate(aggregated_flows.items()):
        if ip_pair in outliers:
            outlier_indices.append(idx)
            outlier_goodput_ratios.append(value["goodputs_ratio"])
            outlier_labels.append(f"{ip_pair}")

    ax.scatter(
        range(len(goodput_ratios)),
        goodput_ratios,
        label="Goodput Ratios",
        alpha=0.6,
        color="b",
    )
    ax.scatter(outlier_indices, outlier_goodput_ratios, color="r", label="Outliers")

    for idx, label in zip(outlier_indices, outlier_labels):
        ax.annotate(
            label,
            (idx, goodput_ratios[idx]),
            textcoords="offset points",
            xytext=(0, 10),
            ha="center",
            rotation=20,
            fontsize=6,
            arrowprops=dict(arrowstyle="-", color="gray"),
        )

    ax.set_title("Scatter Plot of Goodput Ratios with Outliers")
    ax.set_xlabel("Flow Index")
    ax.set_ylabel("Goodput Ratio")
    ax.legend()


def plot_outliers_pie_chart(aggregated_flows, ax, outliers):
    num_outliers = len(outliers)
    num_non_outliers = len(aggregated_flows) - num_outliers

    labels = ["Outliers", "Non-Outliers"]
    sizes = [num_outliers, num_non_outliers]
    colors = ["orangered", "lightskyblue"]

    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
    ax.set_title("Distribution of Outliers and Non-Outliers")
    ax.axis("equal")