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
parser.add_argument("configname", action="store", type=str, help="Configuration to load")

#Load the configuration file for configname
def loadconf(configname, forcereplace):
    hostdir = Path("./hostsconf")
    hostdir.mkdir(parents=True, exist_ok=True)
    try:
        conf_file = open(f"./hostsconf/{configname}.yaml")
        try:
            hostconf = yaml.load(conf_file, Loader=yaml.SafeLoader)
            elog(f"[conf] Loaded config file \'{configname}\'") 
            session = easysnmp.Session(
                hostname="{ip}:{port}".format(ip=hostconf['ip'], port=hostconf['port']),
                community='community' in hostconf.keys() and hostconf['community'] or "public",
                version='version' in hostconf.keys() and hostconf['version'] or 1
            )
            elog("[snmp] Started SNMP session on {ip}:{port}".format(ip=hostconf['ip'], port=hostconf['port']))
            rrdhandler.start(configname, hostconf['step'], hostconf['rrds'], hostconf['graphs'], session, forcereplace)
        except yaml.YAMLError:
            sys.exit(f"The config file '{configname}' is not valid YAML. Exiting.")
    except FileNotFoundError:
        sys.exit(f"The config file '{configname}' doesn't exist. Exiting.")

if __name__ == "__main__":
    arguments = parser.parse_args()
    config.VERBOSE = arguments.v
    loadconf(arguments.configname, arguments.f)
