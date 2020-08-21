from sniffer import *
from devicetable import HostTable
from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import time
import threading
from scapy.all import sniff, datetime
import click

from spoof import Spoofer
from telegramsend import telegramsend


def callperiodically(f, period):
    while 1:
        starttime = time.time()
        f()
        endtime = time.time()
        delta = endtime - starttime
        if period - delta > 0:
            time.sleep(period - delta)


class ArpioTable(HostTable):

    def __init__(self, macnamemap, chatid, telegramtoken):
        super().__init__(macnamemap)
        self.chatid = chatid
        self.token = telegramtoken

    def onnewdevicedetected(self, devinfo):
        super().onnewdevicedetected(devinfo)

        msg = "{}\n{}\n{} : UNKNOWN DEVICE".format(
            datetime.fromtimestamp(devinfo['time']).strftime('%Y-%m-%d %H:%M:%S'),
            devinfo['mac'], devinfo['ip'])
        try:
            telegramsend(msg, self.chatid, self.token)
        except Exception as e:
            print("[!] Error sending telegram message:", e, "Check config json file telegram section")


@click.group()
@click.option('--conf', default='config.json',
              help='configuration file for influxdb, telegram and devices names, default is config.json')
@click.pass_context
def cli(ctx, conf):
    ctx.ensure_object(dict)

    print("[*] Reading config file", conf)
    try:
        with open(conf, 'r') as f:
            config = json.load(f)
            ctx.obj['CONFIG_NAME'] = conf
            ctx.obj['CONFIG'] = config
    except Exception as e:
        print("[!] Error opening config file ", conf, e)
        exit(1)


@cli.command()
@click.option('--arp', is_flag=True, default=False, help='sniff only arp packets')
@click.option('-i', default=None, help='net interface')
@click.pass_context
def netwatch(ctx, arp, i):
    """ Sniffs packets and constructs a presence table for each connected device sending data to influxdb. When an
    unknown device (not present in config file) is detected sends a notification (notify-send), and a message using
    telegram bot (configured in config file) """
    ctx.ensure_object(dict)
    config = ctx.obj['CONFIG']

    fltr = "arp" if arp else "arp or (udp port 5353)"
    sif = i  # or getuserselectedif()

    print("[*] Network interface=", "using default " if not sif else sif, "filter=", fltr)

    pktq = queue.Queue()
    devices = config['devices']
    influxconf = config['influx']
    telegramconf = config['telegram']

    influxclient = InfluxDBClient(url=influxconf["url"], token=influxconf['token'], org=influxconf['org'])
    writeapi = influxclient.write_api(write_options=SYNCHRONOUS)
    table = ArpioTable(devices, telegramconf['chatid'], telegramconf['token'])

    with ThreadPoolExecutor(max_workers=4) as pool:
        pktconsumer = PktConsumer(pktq, pool, daemon=True)

        if influxclient.health().status != 'fail':
            pktconsumer.regcallback(lambda x: influxwrite(x, writeapi, influxconf['bucket'], devices))
            print("[*] Influx health status OK")
        else:
            print("[!] Influx seems unreachable, configure config.json influx section")

        pktconsumer.fastcallback(lambda x: table.submit(x))
        pktconsumer.start()

        t2 = threading.Thread(target=callperiodically, daemon=True, args=(lambda: print(table), 5,))
        t2.start()

        sniff(filter=fltr, iface=sif, prn=lambda x: pktq.put(x), store=0)
        print("[*] Closing...")


@cli.command()
@click.argument('mac')
@click.argument('name')
@click.pass_context
def addname(ctx, mac, name):
    """ Adds a Mac -> Name association to the config file provided (config.json default)"""
    ctx.ensure_object(dict)
    confname = ctx.obj['CONFIG_NAME']
    config = ctx.obj['CONFIG']
    config['devices'][mac] = name

    click.echo('conf file is %s' % config)

    try:
        with open(confname, 'w') as f:
            json.dump(config, f, indent=4, sort_keys=True)
    except Exception as e:
        print(e)


@cli.command()
@click.argument('victimip')
@click.option('--deny', is_flag=True, help='disables ip forwarding')
def spoof(victimip, deny):
    """ Spoofs the target ip, disables ip forwarding with flag --deny """
    with Spoofer(victimip, denyservice=deny) as spoofer:
        spoofer.run()


if __name__ == '__main__':
    cli(obj={})
