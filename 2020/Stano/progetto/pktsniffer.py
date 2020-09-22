import queue
from threading import Thread

from scapy.sendrecv import sniff


class Sniffer(Thread):
    def __init__(self, pktqueue: queue.Queue, bpffilter: str, sif=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sif = sif
        self.q = pktqueue
        self.filter = bpffilter

    def run(self) -> None:
        try:
            sniff(filter=self.filter, iface=self.sif, prn=lambda x: self.q.put(x), store=0)
        except Exception as e:
            print(e)
