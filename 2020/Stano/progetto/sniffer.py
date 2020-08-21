from concurrent.futures.thread import ThreadPoolExecutor
from scapy.all import get_if_list, Packet
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import UDP, IP
from threading import Thread
import queue
from influxdb_client import Point, WriteApi, WritePrecision
from typing import Callable, Any


def getuserselectedif():
    ifs = get_if_list()
    print("Interfaces")
    for i in range(len(ifs)):
        print("- ", i, ifs[i])
    interfaceindex = int(input("Select target interface: "))
    if 0 <= interfaceindex < len(ifs):
        return ifs[interfaceindex]


def mstime(x):
    return int(round(x * 1000))


class PktConsumer(Thread):
    def __init__(self, q: queue.Queue, pool: ThreadPoolExecutor, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cblist = []
        self.fastcblist = []
        self.__queue = q
        self.pool = pool

    def regcallback(self, callback: Callable[[Packet], Any]):
        self.cblist.append(callback)

    def fastcallback(self, fastcallback: Callable[[Packet], Any]):
        self.fastcblist.append(fastcallback)

    def run(self):
        while True:
            pkt: Packet = self.__queue.get()

            for fcb in self.fastcblist:
                fcb(pkt.copy())
            for cb in self.cblist:
                self.pool.submit(cb, pkt.copy())

            self.__queue.task_done()


def influxwrite(pkt: Packet, writeapi: WriteApi, bucket, macnamemap: dict):
    try:
        if pkt.haslayer(ARP):
            p = Point(pkt.hwsrc) \
                .tag("ip", pkt.psrc) \
                .field("presence", 1) \
                .tag('name', macnamemap.get(pkt.hwsrc, "undefined name")) \
                .time(mstime(pkt.time), write_precision=WritePrecision.MS)
            writeapi.write(bucket=bucket, record=p)
            if pkt.op == 2 and pkt.hwdst != "ff:ff:ff:ff:ff:ff":
                p = Point(pkt.hwdst) \
                    .tag("ip", pkt.pdst) \
                    .field("presence", 1) \
                    .tag('name', macnamemap.get(pkt.hwdst, "undefined name")) \
                    .time(mstime(pkt.time), write_precision=WritePrecision.MS)
                writeapi.write(bucket=bucket, record=p)
        elif pkt.haslayer(UDP):
            if Ether in pkt and IP in pkt:
                p = Point(pkt.getlayer(Ether).src) \
                    .tag("ip", pkt.getlayer(IP).src) \
                    .field("presence", 1) \
                    .tag('name', macnamemap.get(pkt.getlayer(Ether).src, "undefined name")) \
                    .time(mstime(pkt.time), write_precision=WritePrecision.MS)
                writeapi.write(bucket=bucket, record=p)
    except Exception as e:
        print("Error writing to influx, configure config.json influx section")
        print(e)
