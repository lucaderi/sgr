import yaml
import easysnmp
import sys
import argparse
import rrdhandler
from pathlib import Path
import config 


def elog(*args, **kwargs):
    if config.VERBOSE:
        print(*args, file=sys.stderr, **kwargs)


parser = argparse.ArgumentParser()
parser.add_argument("-v", action="store_true", help="Enable verbose mode")
parser.add_argument("-f", action="store_true", help="Force replacement of existing RRDs")
parser.add_argument("hostname", action="store", type=str, help="SNMP agent hostname")

#Load the configuration file for hostname
def loadconf(hostname, forcereplace):
    hostdir = Path("./hostsconf")
    hostdir.mkdir(parents=True, exist_ok=True)
    try:
        conf_file = open(f"./hostsconf/{hostname}.yaml")
        try:
            hostconf = yaml.load(conf_file, Loader=yaml.SafeLoader)
            session = easysnmp.Session(
                hostname="{ip}:{port}".format(ip=hostconf['ip'], port=hostconf['port']),
                community='community' in hostconf.keys() and hostconf['community'] or "public",
                version='version' in hostconf.keys() and hostconf['version'] or 1
            )
            elog("[snmp] Started SNMP session on {ip}:{port}".format(ip=hostconf['ip'], port=hostconf['port']))
            rrdhandler.start(hostname, hostconf['step'], hostconf['rrds'], hostconf['graphs'], session, forcereplace)
        except yaml.YAMLError:
            sys.exit(f"The config file for '{hostname}' is not valid YAML. Exiting.")
    except FileNotFoundError:
        sys.exit(f"The config file for '{hostname}' doesn't exist. Exiting.")

if __name__ == "__main__":
    arguments = parser.parse_args()
    config.VERBOSE = arguments.v
    loadconf(arguments.hostname, arguments.f)
