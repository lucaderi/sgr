import yaml
import easysnmp
import jinja2
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
parser.add_argument("hostname", action="store", type=str, help="SNMP agent hostname")

#Load the configuration file for hostname
def loadconf(hostname):
    try:
        conf_file = open(f"./hosts/{hostname}.yaml")
        try:
            config = yaml.load(conf_file, Loader=yaml.SafeLoader)
            session = easysnmp.Session(
                hostname="{ip}:{port}".format(ip=config['ip'], port=config['port']),
                community='community' in config.keys() and config['community'] or "public",
                version='version' in config.keys() and config['version'] or 1
            )
            elog("[SNMP] Started SNMP session on {ip}:{port}".format(ip=config['ip'], port=config['port']))
            print(session.get("sysLocation.0").value)
            rrdhandler.start(hostname, config['data'], session)
        except yaml.YAMLError:
            sys.exit(f"The config file for '{hostname}' is not valid YAML. Exiting.")
    except FileNotFoundError:
        sys.exit(f"The config file for '{hostname}' doesn't exist. Exiting.")

if __name__ == "__main__":
    arguments = parser.parse_args()
    config.VERBOSE = arguments.v
    loadconf(arguments.hostname)
