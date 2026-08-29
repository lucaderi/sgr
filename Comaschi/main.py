import sys
from multiprocessing import Process, Queue
from pyroute2 import IPRoute, IW
import pyprctl
import ifaces_mgmt
import sensor
import analyzer
import gui

PATH_LOSS_EXPONENT = 4.5

def terminate(ip, iw, sniffer, analyzer):
    print("Termination...")
    sniffer.terminate()
    analyzer.terminate()
    sniffer.join(timeout=2)
    analyzer.join(timeout=2)

    state = pyprctl.CapState.get_current()
    state.effective.add(pyprctl.Cap.NET_ADMIN)
    state.effective.add(pyprctl.Cap.NET_ADMIN)
    state.set_current()

    ifaces_mgmt.reset_interface(ip, iw, WIF_NAME, WIPHY_INDEX, MON_IFNAME)
    ip.close()
    iw.close()
    print("Program ended")
    return


#iface setup
ip = IPRoute() 
iw = IW()
result = ifaces_mgmt.research_interface(ip, iw)
if result is None:
    sys.exit(1)
WIF_NAME, WIPHY_INDEX = result

result = ifaces_mgmt.create_monitor_interface(ip, iw, WIF_NAME, WIPHY_INDEX)
if result is None:
    sys.exit(1)
MON_IFNAME, MON_IFINDEX = result

#sniffer setup
packet_queue = Queue()
sniffer_process = Process(target=sensor.sniffer, args=(MON_IFINDEX, MON_IFNAME, packet_queue))
sniffer_process.daemon = True

#analyzer setup
stats_queue = Queue()
analyzer_process = Process(target=analyzer.analyze, args=(packet_queue, stats_queue, PATH_LOSS_EXPONENT))
analyzer_process.daemon = True

#start processes
sniffer_process.start()
analyzer_process.start()

#Discard capabilities
state = pyprctl.CapState.get_current()
state.effective.discard(pyprctl.Cap.NET_ADMIN)
state.effective.discard(pyprctl.Cap.NET_RAW)
state.set_current()

try:
    print("Started")
    app = gui.Dashboard(stats_queue)
    app.mainloop()
    terminate(ip, iw, sniffer_process, analyzer_process)
except KeyboardInterrupt:
    terminate(ip, iw, sniffer_process, analyzer_process)
    



    
