from easysnmp import Session
import plotly.graph_objects as go
import time
import sys
import ipaddress
import math

if (len(sys.argv) < 5) or (len(sys.argv) > 6):
    print("Usage: %s host_ip community version time threshold" % sys.argv[0])
    sys.exit(0)

# ifOutOctets to check the number of transmitted bits from a switch port
OUTOCTETS_OID = '.1.3.6.1.2.1.2.2.1.16.'

#oid to see interfaces status (ifOperStatus)
OPER_STATUS = '.1.3.6.1.2.1.2.2.1.8'

#sysUpTime OID to check if the switch has been reinitialised and the data gathered are no longer reliable
UPTIME = '.1.3.6.1.2.1.1.3.0'

#snmp constants
try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError:
    print("The given IP is wrong")
    sys.exit(0)
HOST = (str)(ip)

COMMUNITY = sys.argv[2]

if (int)(sys.argv[3]) in range(1, 4):
    VERSION = (int)(sys.argv[3])
else:
    print("Version number is incorrect")
    sys.exit(0)

#time constant for calculating mean port usage
TIME = (int)(sys.argv[4])

#constant to define how many active ports the program must use; if not specified the program uses all the ports
if len(sys.argv) == 6:
    THRESHOLD = (int)(sys.argv[5])
else:
    THRESHOLD = math.inf

#function to create a graph
def make_graph(ports, usage, low_lim, up_lim):

    low_list = []
    up_list = []

    for c in range(1, 16):
        low_list.append(low_lim)
        up_list.append(up_lim)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x = ports,
        y = usage,
        marker = dict(color = "gold", size = 12),
        mode = "markers",
        name = "Ports"
    ))

    fig.add_trace(go.Scatter(
        x = ports,
        y = up_list,
        mode = "lines",
        line = dict(color = "red", width = 4),
        name = "Upper limit"
    ))

    fig.add_trace(go.Scatter(
        x = ports,
        y = low_list,
        line = dict(color = "blue", width = 4),
        mode = "lines",
        name = "Lower limit"
    ))

    fig.update_layout(title = "Per port usage", xaxis_title = "Ports numbers", yaxis_title = "Transmitted bits")

    fig.show()

#function to calculate the percentile used to find the outlier ports
def calc_percentile(lst, percentile):

    index = len(lst) * (percentile/100)
    rounded_index = (int)(index + 0.5)

    #element that identiifies the percentile
    found = lst[rounded_index - 1]

    return found

#function to find outliers
def find_outliers(db):

    too_much_traffic = []
    too_few_traffic = []

    ports_list = list(db.keys())
    usage_list = list(db.values())
    
    sorted_usage_lst = sorted(usage_list)

    #q1 and q3 are the percentiles involved in the calculation of the interquartile range (IQR)
    q1 = calc_percentile(sorted_usage_lst, 25)
    q3 = calc_percentile(sorted_usage_lst, 75)
    iqr = q3 - q1
    k = 1.5

    print("Q1: %.1f" % q1)
    print("Q3: %.1f" % q3)
    print("IQR: %.1f" % iqr)

    #normally the lower limit is found with (q1 - k*iqr) expression; 
    #since it's useless for network monitoring to have a negative lower limit, I simply divide q1 by k to have a reasonable lower limit
    lower_limit = q1 / k
    upper_limit = q3 + k*iqr
    print("Lower limit: %f" % lower_limit)
    print("Upper limit: %f" % upper_limit)

    #if an outlier is found, I put the corresponding port number in the correct outlier list
    for key in ports_list:
        if db.get(key) > upper_limit:
            too_much_traffic.append(key)
        elif db.get(key) < lower_limit:
            too_few_traffic.append(key)
    
    print('Too much traffic:\n')
    print(too_much_traffic)
    print('\n')
    print('Too few traffic:\n')
    print(too_few_traffic)

    make_graph(ports_list, usage_list, lower_limit, upper_limit)


#function to evaluate the switch ports usage 
def eval_output_bandwidth(list):

    sessionBandwidth = Session(hostname = HOST, community = COMMUNITY, version = VERSION)

    #dictionary
    usage_db = {}

    print("Evaluating per port usage...\n")

    #time.sleep is used to let the switch send more data
    for port in list:
        upTime1 = sessionBandwidth.get(UPTIME)
        item = sessionBandwidth.get(OUTOCTETS_OID + port)
        firstVal = (int)(item.value)
        time.sleep(TIME)
        upTime2 = sessionBandwidth.get(UPTIME)
        if (int)(upTime1.value) > (int)(upTime2.value):
            print("The switch has been reinitialised: you must restart the monitoring")
            sys.exit(0)
        item2 = sessionBandwidth.get(OUTOCTETS_OID + port)
        secondVal = (int)(item2.value)
        mean_port_usage = (secondVal - firstVal) / TIME
        usage_db.update({port: mean_port_usage})
    
    find_outliers(usage_db)

#function used for polling switch ports
def poll():

    session = Session(hostname = HOST, community = COMMUNITY, version = VERSION)

    walk_result = session.walk(OPER_STATUS)
    active_ports = []
    
    #if item.value is 1 the port is 'up'
    for item in walk_result:
        if (int)(item.value) == 1:
            if len(active_ports) < THRESHOLD:
                active_ports.append(item.oid_index)
    
    print('Active ports')
    print(active_ports)
    print("\n")

    eval_output_bandwidth(active_ports)

poll()  