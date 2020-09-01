#Traffic flow
#!Author: Sacco Giuseppe

from threading import Thread, Lock, Condition
import threading
import psutil
from time import sleep

class PortScanner(Thread):
    def __init__(self, pkt_str):
        threading.Thread.__init__(self)
        self.term = threading.Event()
        self.connections = []
        self.pkt_str = pkt_str

    #scan periodically to find, if any, new process activated
    def run(self):  
        while not self.term.is_set():
            self.connections = psutil.net_connections()
            self.pkt_str.connection = self.connections.copy()
            time.sleep(0.5)

            