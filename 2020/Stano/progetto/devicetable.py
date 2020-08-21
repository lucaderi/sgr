import subprocess as s

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet


class HostTable:
    def __init__(self, macnamemap):
        self.macnamemap = macnamemap
        self.devtable = collections.defaultdict(dict)
        logging.basicConfig(filename='arpio.log', level=logging.INFO)
        self.logger: logging.Logger = logging.getLogger("arpiotable")

    def submit(self, pkt: Packet):
        if pkt.haslayer(ARP):
            self.update(pkt.hwsrc, pkt.psrc, pkt.time)
            # gratuitous case
            if pkt.op == 2 and pkt.hwdst != "ff:ff:ff:ff:ff:ff":
                self.update(pkt.hwdst, pkt.pdst, pkt.time)
        # mDNS
        elif pkt.haslayer(UDP):
            if Ether in pkt and IP in pkt:
                self.update(pkt.getlayer(Ether).src, pkt.getlayer(IP).src, pkt.time)

    def update(self, mac, ip, timestamp):
        if mac in self.devtable:
            self.devtable[mac]["last_seen"] = timestamp
            self.devtable[mac]["ip"] = ip
        else:
            self.devtable[mac]["last_seen"] = timestamp
            self.devtable[mac]["first_seen"] = timestamp
            self.devtable[mac]["ip"] = ip

            if mac in self.macnamemap:
                self.logger.info(
                    "{} {:<15} {} {}".format(datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                                             self.macnamemap[mac], mac, ip))
            else:
                self.onnewdevicedetected(devinfo={"mac": mac, "ip": ip, "time": timestamp})

    def onnewdevicedetected(self, devinfo):
        self.logger.info(
            "{} {} {} : UNKNOWN DEVICE".format(datetime.fromtimestamp(devinfo['time']).strftime('%Y-%m-%d %H:%M:%S'),
                                               devinfo['mac'], devinfo['ip']))
        msg = "MAC: {},\nIP: {}".format(devinfo['mac'], devinfo['ip'])
        s.call(['notify-send', "Arpio: new device detected", msg, "--icon=dialog-information"])

    def __str__(self):
        outstr = "{:<15} {:<18} {:<16} {:>16}\n".format("NAME", "MAC", "IP", "LAST SEEN")
        for key in self.devtable:
            devname = self.macnamemap.get(key, "undefined name")
            deltatime = int(time.time() - self.devtable[key]["last_seen"])
            days = divmod(deltatime, 86400)
            hours = divmod(days[1], 3600)
            minutes = divmod(hours[1], 60)
            seconds = divmod(minutes[1], 1)
            outstr += "{:<15} {:<18} {:<16} {:>4}d {:>2}h {:>2}m {:>2}s ago\n".format(devname, key,
                                                                                      self.devtable[key]["ip"], days[0],
                                                                                      hours[0], minutes[0], seconds[0])
        return outstr
