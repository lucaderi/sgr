import config
import rrdtool
import time
import re
from time import sleep
from pathlib import Path
from main import elog
from jinja2 import Environment, FileSystemLoader, select_autoescape

dsregexp = re.compile("DS:(.+):(.+):(\d+):(.+):(.+)")
rraregexp = re.compile("RRA:(.+):(.+):(.+):(.+)")

env = Environment(
    loader=FileSystemLoader("."),
    autoescape=select_autoescape(['html', 'xml'])
)

def rrd_check_equality(hostname, rrd_name, rrd_conf):
    dsequality = False
    rraequality = False
    
    try:
        info = rrdtool.info(f"rrd/{hostname}/{rrd_name}.rrd")
        if info['step'] != config.STEP:
            return False
    except rrdtool.OperationalError:
        return False

    for ds_def in rrd_conf['ds']:
        try:
            groups = dsregexp.match(ds_def).groups()
            key = "ds[{0}]".format(groups[0])
            dsequality = info[f"{key}.type"] == groups[1] and str(info[f"{key}.minimal_heartbeat"]) == groups[2]
        except KeyError:
            return False

    for index, rra_def in enumerate(rrd_conf['rra']):
        try:
            groups = rraregexp.match(rra_def).groups()
            key = f"rra[{index}]"
            rraequality = info[f"{key}.cf"] == groups[0] and str(info[f"{key}.rows"]) == groups[3] and str(info[f"{key}.pdp_per_row"]) == groups[2]
        except KeyError:
            return False

    return dsequality and rraequality
        

def rrdcreate_to_tuple(hostname, name, rrd):
    print(config.STEP)
    return (f"rrd/{hostname}/{name}.rrd", "--start", "now", "--step", str(config.STEP), *rrd['ds'], *rrd['rra'])

def rrdupdate_to_list(queries, session):
    #Build --template flag
    args = ["--template", ":".join(list(queries.keys()))]
    
    #Query the SNMP agent
    values = [session.get(oid).value for oid in queries.values()]
    
    #Join both template and values
    args.append("N:{0}".format(":".join(values)))
    return args

def rrdgraph_to_list(graph_conf):
    #Use SVG by default
    lst = ["--imgformat", config.IMGFORMAT.upper()]

    #Build options list
    for option, value in graph_conf['options'].items():
        lst.append(f"--{option}")
        lst.append(value)

    #Add all the defs
    lst.extend(graph_conf['defs'])
    return lst

def writetemplate(hostname, graphs_conf):
    with open(f"{hostname}.html", "w") as f:
        f.write(env.get_template("default.jinja").render(hostname=hostname, graph_root=config.GRAPH_ROOT, graphs=list(graphs_conf.keys()), step=config.STEP * 1000))

def runupdate(hostname, rrds_conf, graphs_conf, session):
    #Update the RRDs
    while True:
        for rrd_name in rrds_conf.keys():
            rrdtool.update(f"rrd/{hostname}/{rrd_name}.rrd", *rrdupdate_to_list(rrds_conf[rrd_name]['snmpqueries'], session))
            elog(f"[rrd] Updated {hostname}/{rrd_name}.rrd")
        for graph_name in graphs_conf.keys():
            rrdtool.graph(f"{config.GRAPH_ROOT}/{hostname}/{graph_name}.{config.IMGFORMAT}", *rrdgraph_to_list(graphs_conf[graph_name]))
            elog(f"[graph] Updated graph on {config.GRAPH_ROOT}/{hostname}/{graph_name}.{config.IMGFORMAT}")
        #...and update the graphs
        sleep(config.STEP)

            

def start(hostname, step, rrds_conf, graphs_conf, session, forcereplace):

    config.STEP = step

    rrdfolder = Path(f"rrd/{hostname}")
    rrdfolder.mkdir(parents=True, exist_ok=True)

    graphfolder = Path(f"{config.GRAPH_ROOT}/{hostname}")
    graphfolder.mkdir(parents=True, exist_ok=True)

    for rrd_name in rrds_conf.keys():
        if (not rrd_check_equality(hostname, rrd_name, rrds_conf[rrd_name]['rrd'])) or forcereplace:
            elog(f"[rrd] Created RRD {hostname}/{rrd_name}.rrd")
            rrdtool.create(*rrdcreate_to_tuple(hostname, rrd_name, rrds_conf[rrd_name]['rrd']))

    writetemplate(hostname, graphs_conf)
    runupdate(hostname, rrds_conf, graphs_conf, session)