import numpy as np
import pandas as pd

def tot_bytes(data):
    s_to_c_bytes = data["s_to_c_bytes"].dropna()
    c_to_s_bytes = data["c_to_s_bytes"].dropna()

    s_to_c_tot = np.sum(s_to_c_bytes)
    c_to_s_tot = np.sum(c_to_s_bytes)
    tot_bytes = s_to_c_tot + c_to_s_tot

    return s_to_c_tot, c_to_s_tot, tot_bytes


def tot_goodput_bytes(data):
    s_to_c_goodput_bytes = data["s_to_c_goodput_bytes"].dropna()
    c_to_s_goodput_bytes = data["c_to_s_goodput_bytes"].dropna()

    s_to_c_tot = np.sum(s_to_c_goodput_bytes)
    c_to_s_tot = np.sum(c_to_s_goodput_bytes)
    tot_goodput_bytes = s_to_c_tot + c_to_s_tot

    return s_to_c_tot, c_to_s_tot, tot_goodput_bytes


def tot_pkts(data):
    s_to_c_pkts = data["s_to_c_pkts"].dropna()
    c_to_s_pkts = data["c_to_s_pkts"].dropna()

    s_to_c_tot = np.sum(s_to_c_pkts)
    c_to_s_tot = np.sum(c_to_s_pkts)
    tot_pkts = s_to_c_tot + c_to_s_tot

    return s_to_c_tot, c_to_s_tot, tot_pkts

def iat_flow_avg(data):
    flows_avg = data["iat_flow_avg"].dropna()
    flows_avg = np.mean(flows_avg)
    
    return flows_avg

def packet_len_distribution(data):
    pktlen_c_to_s_avg = data['pktlen_c_to_s_avg'].dropna()
    pktlen_s_to_c_avg = data['pktlen_s_to_c_avg'].dropna()

    all_pktlen_avg = pd.concat([pktlen_c_to_s_avg, pktlen_s_to_c_avg])

    bins = [0, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120, np.inf]
    hist, bin_edges = np.histogram(all_pktlen_avg, bins=bins)

    total_packets = np.sum(hist)
    percentages = (hist / total_packets) * 100

    return hist, bin_edges, percentages


def flow_duration_distribution(data):
    durations = data['duration'].dropna()
    bins = [0, 1, 5, 10, 30, 60, 300, 600, np.inf]
    hist, bin_edges = np.histogram(durations, bins=bins)
    return hist, bin_edges

def top_talkers(data, n=10):
    traffic_by_ip = data.groupby('src_ip')['c_to_s_bytes'].sum()
    top_talkers = traffic_by_ip.sort_values(ascending=False).head(n)
    return top_talkers

def avg_flow_duration(data):
    duration = data['duration'].dropna()
    avg_duration = np.mean(duration)
    return avg_duration

def total_flows(data):
    total = len(data)
    return total

def traffic_distribution_by_protocol(data):
    protocol_distribution = data.groupby('ndpi_proto')['c_to_s_bytes'].sum()
    total_traffic = protocol_distribution.sum()
    percentages = (protocol_distribution / total_traffic) * 100
    return protocol_distribution, percentages

def iat_statistics(data):
    iat_flow_min = np.min(data['iat_flow_min'].dropna())
    iat_flow_max = np.max(data['iat_flow_max'].dropna())
    iat_flow_avg = np.mean(data['iat_flow_avg'].dropna())
    
    return iat_flow_min, iat_flow_max, iat_flow_avg



