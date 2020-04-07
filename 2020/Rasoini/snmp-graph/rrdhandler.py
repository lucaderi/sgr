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

def rrdcreate_to_list(hostname, name, step, rrd):
    return (f"rrd/{hostname}/{name}.rrd", "--start", "now", "--step", str(step), *rrd['ds'], *rrd['rra'])

def rrdupdate_to_list(queries, session):
    #Build --template flag
    args = ["--template", ":".join(list(queries.keys()))]
    
    #Query the SNMP agent
    values = [session.get(oid).value for oid in queries.values()]
    
    #Join both template and values
    args.append("N:{0}".format(":".join(values)))
    return args

def rrdgraph_to_list(name, hostconf):
    #Use SVG by default
    tup = ["--imgformat", config.IMGFORMAT.upper()]
    for option, value in hostconf[name]['rrd']['graph']['options'].items():
        tup.append(f"--{option}")
        tup.append(value)
    tup.extend(hostconf[name]['rrd']['graph']['defs'])
    return tup

def writetemplate(hostname, step, hostconf):
    with open(f"{hostname}.html", "w") as f:
        f.write(env.get_template("default.template").render(hostname=hostname, graph_root=config.GRAPH_ROOT, svgs=list(hostconf.keys()), step=step * 1000))

def runupdate(hostname, step, hostconf, session):
    #Update the RRDs
    for name in hostconf.keys():
        rrdtool.update(f"rrd/{hostname}/{name}.rrd", *rrdupdate_to_list(hostconf[name]['snmpqueries'], session))
        rrdtool.graph(f"{config.GRAPH_ROOT}/{hostname}/{name}.{config.IMGFORMAT}", *rrdgraph_to_list(name, hostconf))
    #...and update the graphs
    elog("[RRD] Updated RRDs")
    thread = threading.Timer(step, runupdate, args=(hostname, step, hostconf, session))
    thread.start()

            

def start(hostname, step, hostconf, session):
    rrdfolder = Path(f"rrd/{hostname}")
    rrdfolder.mkdir(parents=True, exist_ok=True)
    graphfolder = Path(f"{config.GRAPH_ROOT}/{hostname}")
    graphfolder.mkdir(parents=True, exist_ok=True)
    for measurement in hostconf.keys():
        rrdtool.create(*rrdcreate_to_list(hostname, measurement, step, hostconf[measurement]['rrd']['create']))
    writetemplate(hostname, step, hostconf)
    runupdate(hostname, step, hostconf, session)