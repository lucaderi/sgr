#!/usr/bin/env python3

from sklearn.cluster import DBSCAN
from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse
import numpy as np


def updatechain(who, slot, flows):
    if (not (who in flows)):
        # tuple that says to which cluster it belongs
        flows[who] = [newchain(), -1]

    flows[who][0][slot] = flows[who][0][slot] + 1


def newchain():
    c = [0 for x in range(maxlen)]
    return c


def scale(len):
    if (len > 1504):
        len = 1504

    return (int(len / 64))


def printchain(a):
    s = sum(a)
    for x in range(maxlen):
        a[x] = int((a[x] * 100) / s)

    # print(a)
    return a


def calc_dist(pcap):
    print("Analyzing pcap: ", args.pcap)
    print("Using BPF filter: ", args.filter)

    caps = None
    try :
        caps = sniff(offline=args.pcap, filter=args.filter)
    except Scapy_Exception:
        print("Please use an valid pcap file!")
        sys.exit(1)
    flows = {}

    for el in [cap for cap in caps if (IP and TCP) in cap]:
        who = (el[IP].src + ":" + str(el[TCP].sport), "to", el[IP].dst + ":" + str(el[TCP].dport))
        updatechain(who, scale(len(el[IP])), flows)

    """for host in flows:
        print("Flow " + str(host))
        printchain(flows[host])"""

    avg = np.array(newchain())
    count = 0
    dist_list = []

    """for host in flows:
        count += 1
        avg += np.array(flows[host])
        dist_list.append(np.array(flows[host]))"""

    dist_list = [np.array(flows[host][0]) for host in flows]
    # qprint(dist_list)
    labels = {}
    clustering = None;
    try:
        clustering = DBSCAN(eps=args.eps, min_samples=args.samples).fit(dist_list)
    except ValueError:
        print("You're probably using an unsupported pcap, only TCP flows are supported right now.")
        sys.exit(1)
    # print(clustering.labels_)

    cluster_avg = {}

    for host, label in zip(flows, clustering.labels_):
        if label in cluster_avg:
            cluster_avg[label][0] += flows[host][0]
            cluster_avg[label][1] += 1
        else:
            cluster_avg[label] = [np.array(newchain()), 0]
            cluster_avg[label][0] = cluster_avg[label][0] + np.array(flows[host][0])
            cluster_avg[label][1] = 1

    # scaling distributions to percentages
    for el in cluster_avg:
        cluster_avg[el][0] = printchain(cluster_avg[el][0])
        # print(cluster_avg[el][0])

    # print(cluster_avg)

    # put the correct labels to the hosts
    for host, label in zip(flows, clustering.labels_):
        flows[host][1] = label
        # print(host, label)

    np.set_printoptions(precision=3)

    for label in set(clustering.labels_):

        if label >= 0:
            print("Cluster {:d}, average distribution: ".format(label))
            print(",".join(map(str, cluster_avg[label][0].tolist())))
        else:
            print("Undetected flows, average distribution: ".format(label))
            print(",".join(map(str, cluster_avg[label][0].tolist())))

        for host in flows:
            if flows[host][1] == label:
                avg = printchain(flows[host][0])
                similarity = np.linalg.norm(avg - np.array(cluster_avg[label][0]))
                print(host, "average distribution", ",".join(map(str, avg)),
                      "similarity to cluster avg: {:.2f}".format(similarity))


maxlen = int(1504 / 32)

parser = argparse.ArgumentParser(description='Plot packet length distribution comparing'
                                             ' it to its mean cluster distribution average.')
parser.add_argument('pcap', metavar='P', nargs="+", help='the pcap to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='an optional filter in BPF syntax to be applied to the pcap.',
                    default="")
parser.add_argument('-e', metavar='E', dest="eps", type=float,
                    help='DBSCAN distance hyperparameter. default = 8',
                    default=8)
parser.add_argument('-m', metavar='M', dest="samples", type=int,
                    help='DBSCAN minimum samples hyperparameter. default = 5',
                    default=5)

args = parser.parse_args()

calc_dist(args.pcap[0])
