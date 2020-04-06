import config
import rrdtool
import time
import threading
from pathlib import Path
from main import elog
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader("."),
    autoescape=select_autoescape(['html', 'xml'])
)

def rrdcreate_to_tuple(hostname, name, rrd):
    return (f"rrd/{hostname}/{name}.rrd", "--start", "now", "--step", str(rrd["step"]), *rrd['ds'], *rrd['rra'])

def rrdgraph_to_tuple(name, data):
    tup = []
    for option, value in data[name]['rrd']['graph']['options'].items():
        tup.append(f"--{option}")
        tup.append(value)
    tup.extend(data[name]['rrd']['graph']['def'])
    return tup

def writetemplate(hostname, data):
    with open(f"{hostname}.html", "w") as f:
        f.write(env.get_template("default.template").render(hostname=hostname, svgs=list(data.keys())))

def runupdate(hostname, data, session):
    elog("[RRD] Updated RRDs")
    for name in data.keys():
        val = session.get(data[name]['snmpquery']).value
        rrdtool.update(f"rrd/{hostname}/{name}.rrd", f"N:{val}")
        rrdtool.graph(f"rrd/{hostname}/{name}.svg", *rrdgraph_to_tuple(name, data))
    thread = threading.Timer(15.0, runupdate, args=(hostname, data, session))
    thread.start()

            

def start(hostname, data, session):
    folder = Path(f"rrd/{hostname}")
    folder.mkdir(parents=True, exist_ok=True)
    for rrd in data.keys():
        rrdtool.create(*rrdcreate_to_tuple(hostname, rrd, data[rrd]['rrd']['create']))
    writetemplate(hostname, data)
    thread = threading.Timer(15.0, runupdate, args=(hostname, data, session))
    thread.start()


        
    