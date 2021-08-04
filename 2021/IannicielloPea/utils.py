import argparse
import sflow
from datetime import datetime

BUF_MAX = 2048


# function for writing bytes in a cleaner way
def prettify_bytes(bytes):
    if bytes < 10000:
        return f'{bytes // 1}'
    elif bytes < 10000000:
        return f'{bytes // 1000}K'
    elif bytes < 10000000000:
        return f'{bytes // 1000000}M'
    else:
        return f'{bytes // 1000000000}G'


# function for handling divisions with 0
def safe_div(a, b):
    if a == 0 or b == 0: return 0
    return a / b


# function for calculating the correct number of samples and sample pool
def parse_sp(sflow_data: sflow.sFlow, SP: tuple, samples: int):
    iSP, lSP = SP
    for sample in sflow_data.samples:
        if sample.sample_type == 1:         
            samples += 1
            if iSP == -1: iSP = sample.sample_pool
            lSP = sample.sample_pool
    return ((iSP, lSP), samples)


# function for updating the IPs with the corresponding bytes and packets sent and received
def parse_ips(sflow_data: sflow.sFlow, oldIPs: dict):
    new_values = False
    for sample in sflow_data.samples:
        for record in sample.records:
            if record.record.__class__ == sflow.sFlowRawPacketHeader:
                rec: sflow.sFlowRawPacketHeader = record.record
                if rec.ip:
                    new_values = True
                    if rec.ip_source not in oldIPs:
                        oldIPs[rec.ip_source] = (0, 0, 0, 0)
                    if rec.ip_destination not in oldIPs:
                        oldIPs[rec.ip_destination] = (0, 0, 0, 0)
                    
                    oldIPs[rec.ip_source] = (oldIPs[rec.ip_source][0], oldIPs[rec.ip_source][1], oldIPs[rec.ip_source][2]  + rec.ip_total_length + rec.ip_header_legth, oldIPs[rec.ip_source][3] + 1)
                    
                    oldIPs[rec.ip_destination] = (oldIPs[rec.ip_destination][0] + rec.ip_total_length + rec.ip_header_legth, oldIPs[rec.ip_destination][1] + 1, oldIPs[rec.ip_destination][2] , oldIPs[rec.ip_destination][3])
                   
    return (oldIPs, new_values)


# function for parsing arguments
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="sFlow collector to find top talkers in a network"
    )
    parser.add_argument(
        '-p', metavar='port', type=int, help='sFlow collector port', default=6343
    )
    parser.add_argument(
        '-a', metavar='address', help='sFlow collector ip', default='127.0.0.1'
    )
    parser.add_argument(
        '-m', metavar='max_talkers', type=int, help='Max number of talkers to display, 0 for unlimited', default=0
    )
    args = parser.parse_args()
    return args