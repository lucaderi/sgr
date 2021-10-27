class AP:
    """ An object that represents an Access Point seen in the environment.
    Inputs:
    - bssid(str) the MAC address of the device sending beacon frames
    - ssid(str) the network name of the device sending beacon frames
    """
    def __init__(self, bssid, ssid):
        self.bssid = bssid
        self.ssid = ssid

    def printAP(self):
        print(self.bssid + "    " + self.ssid)
