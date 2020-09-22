import queue
import time
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from threading import Thread
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP
from scapy.packet import Packet
from kvstore import KVstore
from telegramsend import TelegramSender

delta_new_activity = 3600 * 6
db_name = "kv.db"


class Consumer(Thread):
    def __init__(self, pktqueue: queue.Queue, thpool: ThreadPoolExecutor, telegram_sender: TelegramSender,
                 send_influxdb, *args,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.send_influxdb = send_influxdb
        self.telegram_sender = telegram_sender
        self.q = pktqueue
        self.thpool = thpool
        self.kv = KVstore(db_name)

    def run(self) -> None:
        while True:
            try:
                pkt = self.q.get()
                self.submit(pkt)
                self.q.task_done()
            except Exception as exc:
                print(exc)

    def submit(self, pkt: Packet):
        if pkt.haslayer(ARP):
            eth_src = pkt.getlayer(Ether).src
            if eth_src == "ff:ff:ff:ff:ff:ff" or eth_src == "00:00:00:00:00:00" or pkt.hwsrc == "ff:ff:ff:ff:ff:ff" or pkt.hwsrc == "00:00:00:00:00:00":
                self.on_eth_broadcast(pkt)
                return
            if eth_src != pkt.hwsrc:  # source mac arp mismatch
                self.on_eth_mismatch(pkt)
            if pkt.psrc != '0.0.0.0' and pkt.psrc != '255.255.255.255':
                self.update(pkt.hwsrc, pkt.psrc, pkt.time)
                if pkt.op == 2 and pkt.hwdst != "ff:ff:ff:ff:ff:ff" and pkt.hwdst != "00:00:00:00:00:00":
                    self.update(pkt.hwdst, pkt.pdst, pkt.time)
        elif Ether in pkt and IP in pkt and pkt.getlayer(IP).src != '0.0.0.0' \
                and pkt.getlayer(IP).src != '255.255.255.255':
            self.update(pkt.getlayer(Ether).src, pkt.getlayer(IP).src, pkt.time)

    def update(self, mac, ip, timestamp):
        if mac in self.kv:
            val = self.kv[mac]
            if timestamp - val["last_seen"] > delta_new_activity:
                self.on_new_activity(mac, ip, timestamp)
            val["last_seen"] = timestamp
            val["ip"] = ip
            self.kv[mac] = val
        else:
            val = {
                "last_seen": timestamp,
                "first_seen": timestamp,
                "ip": ip
            }
            self.kv[mac] = val
            self.on_new_mac(mac, ip, timestamp)
        self.thpool.submit(self.send_influxdb, mac, ip, timestamp, self.get_alias(mac))

    def on_eth_mismatch(self, pkt: Packet):
        msg = "ETH_MISMATCH\nNAME = {}\n{}".format(self.get_alias(pkt.getlayer(Ether).src), pkt.show(dump=True))
        self.send_to_telegram(msg)

    def on_eth_broadcast(self, pkt):
        msg = "ETH_BROADCAST\n" + pkt.show(dump=True)
        self.send_to_telegram(msg)

    def on_new_mac(self, mac, ip, timestamp):
        msg = f"{datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}\nNEW_MAC\nMAC = {mac} \nIP = {ip} "
        self.send_to_telegram(msg)

    def on_new_activity(self, mac, ip, timestamp):
        msg = f"{datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}\nNEW_ACTIVITY\nNAME = {self.get_alias(mac)}\nMAC = {mac} \nIP = {ip} "
        self.send_to_telegram(msg)

    def send_to_telegram(self, msg):
        self.thpool.submit(self.telegram_sender.send_msg, msg)

    def get_alias(self, mac):
        try:
            val = self.kv[mac]
            alias = val.get("alias", "undefined")
            return alias
        except Exception:
            return "undefined"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.kv.close()


def printtable():
    try:
        with KVstore(db_name) as kv:
            outstr = "{:<15} {:<18} {:<16} {:>16}\n".format("NAME", "MAC", "IP", "LAST SEEN")
            for key, v in kv.iteritems():
                devname = v.get("alias", "undefined")
                deltatime = int(time.time() - v["last_seen"])
                days = divmod(deltatime, 86400)
                hours = divmod(days[1], 3600)
                minutes = divmod(hours[1], 60)
                seconds = divmod(minutes[1], 1)
                outstr += "{:<15} {:<18} {:<16} {:>4}d {:>2}h {:>2}m {:>2}s ago\n".format(devname, key,
                                                                                          v["ip"], days[0],
                                                                                          hours[0], minutes[0],
                                                                                          seconds[0])
            print(outstr)
    except Exception as e:
        print(e)
