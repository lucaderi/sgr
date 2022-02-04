import queue
from concurrent.futures.thread import ThreadPoolExecutor
from influxsend import influx_writepoint
from kvstore import KVstore
from pktconsumer import Consumer, printtable, db_name
from pktsniffer import Sniffer
from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import time
import threading
import click

from telegramsend import TelegramSender


def callperiodically(f, period):
    while 1:
        starttime = time.time()
        f()
        endtime = time.time()
        delta = endtime - starttime
        if period - delta > 0:
            time.sleep(period - delta)


@click.group()
@click.option('--conf', default='config.json',
              help='configuration file for influxdb, telegram. Default is config.json')
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
    """Monitors devices presence in the local network, sending data to Influxdb and alerts via Telegram"""
    ctx.ensure_object(dict)
    config = ctx.obj['CONFIG']

    fltr = "arp" if arp else "ether[0]&1=1"
    sif = i

    print("[*] Network interface =", "any " if not sif else sif, "filter =", fltr)
    pktq = queue.Queue()

    influxconf = config['influx']
    influxclient = InfluxDBClient(url=influxconf["url"], token=influxconf['token'], org=influxconf['org'])
    writeapi = influxclient.write_api(write_options=SYNCHRONOUS)

    def send_influxdb(mac, ip, timestamp, name):
        influx_writepoint(mac, ip, name, timestamp, writeapi=writeapi, bucket=influxconf['bucket'])

    telegramconf = config['telegram']
    t_sender = TelegramSender(telegramconf["token"], telegramconf["chatid"])

    pkt_sniffer = Sniffer(pktq, fltr, sif, daemon=True)

    with ThreadPoolExecutor(max_workers=4) as thpool, Consumer(pktq, thpool, t_sender, send_influxdb) as consumer:
        pkt_sniffer.start()
        t2 = threading.Thread(target=callperiodically, daemon=True, args=(lambda: printtable(), 5,))
        t2.start()
        consumer.run()


@cli.command()
@click.argument('mac')
@click.argument('name')
def addname(mac, name):
    """ Adds a Mac -> Name association"""
    with KVstore(db_name) as kv:
        val = kv[mac]
        val["alias"] = name
        kv[mac] = val
        print("Added mac name association {} -> {}".format(mac, name))


if __name__ == '__main__':
    cli(obj={})
