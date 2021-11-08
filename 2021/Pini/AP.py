class AP:
    """ An object that represents an Access Point seen in the environment.
    Inputs:
    - bssid(str) the MAC address of the device sending beacon frames
    - ssid(str) the network name of the device sending beacon frames
    - rssi(int) the received signal strength
    - crypto the type of security used in the network (of the AP)
    """
    def __init__(self, bssid, ssid, rssi, crypto):
        self.bssid = bssid
        self.ssid = ssid
        self.rssi = rssi
        self.crypto = crypto

    def printAP(self):
        padding = 1 + (32-len(self.ssid))   # 32 is the max SSID length
        print(self.bssid + "    " + self.ssid + " "*padding + str(self.rssi) + " dBm -> " + self.__evalRssi() + str(self.crypto))
    
    def __evalRssi(self):
        if self.rssi >= -50:
            return "Excellent  "
        if self.rssi >= -70:
            return "Good       "
        return "Low        "
