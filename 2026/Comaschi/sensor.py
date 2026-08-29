import time
import pcapy
from pyroute2 import IW, IPRoute
from multiprocessing import Queue
from ifaces_mgmt import set_channel

def sniffer(ifindex, mon_ifname, pkt_queue:Queue):
    iw = IW()
    TWO_GHZ_BASE_FREQ = 2412
    TWO_GHZ_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    FIVE_GHZ_BASE_FREQ = 5000 
    FIVE_GHZ_CHANNELS = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    #Crea dict canale-frequenza
    freq_table = dict()
    for ch in TWO_GHZ_CHANNELS:
        freq_table[ch] = TWO_GHZ_BASE_FREQ + (ch - 1)*5
    for ch in FIVE_GHZ_CHANNELS:
        freq_table[ch] = FIVE_GHZ_BASE_FREQ + ch*5

    CHANNELS = [[ch, 0] for ch in (TWO_GHZ_CHANNELS + FIVE_GHZ_CHANNELS)]
    SNAPLEN = 65535 #default
    TIMEOUT = 100
    WAIT_TIME = 0.25 #sembra essere un buon valore per massimizzare pkts/sec catturati
    BURST_INDEX = 500
    cooldown_rounds = 0
    smoothing_factor = 0.8 #rende l'ema molto reattiva
    inizialization = True
    empty_channels = list()
    packets = list()

    def callback(header, packet):
        send_header = (header.getts()[0], header.getlen()) 
        packets.append((send_header, packet))

    try:
        cap = pcapy.open_live(mon_ifname, SNAPLEN, 1, TIMEOUT)
        cap.setnonblock(True)
        while(True):
            if len(empty_channels) != 0:
                empty_channels.pop(0)
            total_pkts = 0
            channels_listened = 0
            for ch in CHANNELS:
                if ch[0] not in empty_channels:
                    if set_channel(iw, ifindex, ch[0], freq_table) != 0:
                        print(f"Unable to set {mon_ifname} on channel {ch[0]}")
                        continue
                    channels_listened += 1
                    time.sleep(WAIT_TIME)
                    packet_count = cap.dispatch(-1, callback)
                    if inizialization:
                        ema = packet_count
                        ema_prev = ema
                        SEND_THRESHOLD = ema
                        inizialization = False
                    else:
                        ema_prev = ema
                        ema = (packet_count*smoothing_factor) + (ema*(1-smoothing_factor))
                        if packet_count == 0:
                            empty_channels.append(ch[0])
                            print(f"No packets found on channel {ch[0]}")
                        else:
                            total_pkts += packet_count
                            ch[1] = packet_count
                            print(f"Found {packet_count} packets on channel {ch[0]}")
                    
                    if not cooldown_rounds:
                        SEND_THRESHOLD = int(ema)
                        print(f"SEND TRESHOLD: {SEND_THRESHOLD}")

                    delta_ema = ema - ema_prev
                    if delta_ema >= BURST_INDEX:
                        cooldown_rounds += 1
                    elif cooldown_rounds > 0:   
                        cooldown_rounds -= 1

                    if len(packets) >= SEND_THRESHOLD:
                        pkt_queue.put(list(packets))
                        packets.clear()
                        print("Packets sent to queue")

            CHANNELS.sort(key = lambda x: x[1], reverse = True)
            pkts_per_sec = int(total_pkts // (channels_listened * WAIT_TIME))
            print(f"PKTS PER SECOND: {pkts_per_sec}")
            print(f"SEND TRESHOLD: {SEND_THRESHOLD}")
    except pcapy.PcapError as e:
        print(f"Error capturing packets: {e}")



if __name__ == '__main__':
    pull_queue = Queue()
    with IW() as iw, IPRoute() as ip:
        ifindex = ip.link_lookup(ifname = 'wlo1mon')[0]
        sniffer(iw, ifindex, 'wlo1mon', pull_queue)
    





    


