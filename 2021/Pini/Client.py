
class Client:
    """Represents a wireless client seen in that envirement

    Inputs:
    - bssid(str) the MAC address of the wireless client
    - ssid set of the network names (of the APs)

    """
    def __init__(self, bssid):
        self.bssid = bssid
        self.requested_ssid = set()
    
    def add_new_requested_ssid(self, new_ssid):
        """ Returns True if new_ssid was not present and for that added, False otherwise """
        if new_ssid not in self.requested_ssid:
            self.requested_ssid.add(new_ssid)
            return True
        return False

    def printClient(self):
        ssid_list  = []
        for item in self.requested_ssid:
            ssid_list.append(item)
        if len(ssid_list) == 0:
            print(self.bssid)
            return
        print(self.bssid + "    " + ssid_list[0])
        x = 1
        while x < len(ssid_list):
            print(" "*17 + "    " + ssid_list[x])
            x = x + 1


