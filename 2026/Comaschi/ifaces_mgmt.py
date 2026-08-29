from pyroute2 import IPRoute, IW 
from pyroute2.netlink import NetlinkError
from pyroute2.netlink.nl80211 import nl80211cmd
from pyroute2.netlink.nl80211 import NL80211_NAMES
from pyroute2.netlink import NLM_F_REQUEST, NLM_F_ACK

#Trova un interfaccia wireless associata ad un'interfaccia fisica
def research_interface(ip: IPRoute, iw: IW): 
    ifaces = ip.get_links()
    wif_name = None
    wiphy_index = None
    for iface in ifaces:
        ifindex = iface['index']
    
        try:
            wirless_iface = iw.get_interface_by_ifindex(ifindex) #Cerca l'interfaccia passata per indice tra le interfacce wireless
            wif_attributes = dict(wirless_iface[0]['attrs'])
            wif_name = wif_attributes.get('NL80211_ATTR_IFNAME')
            wiphy_index = wif_attributes.get('NL80211_ATTR_WIPHY')
            if wif_name and wiphy_index is not None:
                wiphy = 'phy' +  str(wiphy_index)
                print(f"Found: {wif_name} on {wiphy}")
                return (wif_name,  wiphy_index)
        
        except NetlinkError as e:
            if e.code == 19: # 19 = l'interfaccia non esiste
                pass
            else: 
                print(f"Error while searching for an available interface: {e}")
    return None

#Elimina l'interfaccia passata come parametro e la ricrea in modalità monitor
def create_monitor_interface(ip: IPRoute, iw: IW, wif_name, wiphy_index): 
    mon_ifname = wif_name + "mon"
    try:
        idx = ip.link_lookup(ifname = wif_name)[0]
        ip.link('set', index = idx, state = 'down') 
        iw.del_interface(idx) #rimuove l'interfaccia con l'indice specificato
    except NetlinkError as e:
        print(f"Errore while deleting the interface {wif_name}: {e}")
        return None
    try:
        iw.add_interface(ifname=mon_ifname, iftype='monitor', phy=wiphy_index)
    except NetlinkError as e:
        print(f"Errore in the creation of the monitor interface: {e}")
        return None
    try:
        mon_idx = ip.link_lookup(ifname = mon_ifname)[0]
        ip.link('set', index = mon_idx, state = 'up')
    except NetlinkError as e:
        print(f"Error activating the monitor interface {mon_ifname}: {e}")
        return None
    return (mon_ifname, mon_idx)

#Elimina l'interfaccia monitor passata come parametro e la ricrea in modalità managed
def reset_interface(ip:IPRoute, iw:IW, wif_name, wiphy_index, mon_ifname):
    try:
        monitor_idx = ip.link_lookup(ifname = mon_ifname)[0] 
        ip.link('set', index = monitor_idx, state = 'down')
        iw.del_interface(monitor_idx)
    except NetlinkError as e:
        print(f"Error while deleting the monitor interface {mon_ifname}: {e}")
        return None
    try:
        iw.add_interface(wif_name, iftype='station', phy=wiphy_index)
    except NetlinkError as e:
        print(f"Error in the creation of the managed interface {wif_name}: {e}")
        return None
    try:
        managed_idx = ip.link_lookup(ifname = wif_name)[0]
        ip.link('set', index = managed_idx, state = 'up')
    except NetlinkError as e:
        print(f"Error activating the managed interface {wif_name}: {e}")
    return wif_name

#Imposta l'interfaccia sul canale specificato
def set_channel(iw:IW, ifindex, ch, freq_table):
    freq = freq_table.get(ch)
    try:
        msg = nl80211cmd()
        msg['cmd'] = NL80211_NAMES['NL80211_CMD_SET_CHANNEL']
        msg['attrs'] = [['NL80211_ATTR_IFINDEX', ifindex], ['NL80211_ATTR_WIPHY_FREQ', freq]]
        iw.nlm_request(msg, iw.prid, NLM_F_REQUEST | NLM_F_ACK)
    except NetlinkError as e:
        print(e)
        return 1
    return 0

    


if __name__ == '__main__':
    with IPRoute() as ip, IW() as iw:
        #create_monitor_interface(ip, iw, 'wlo1', 0)
        reset_interface(ip, iw, 'wlo1', 0, 'wlo1mon')
        #print(set_channel(iw, 22, 0, [5180]))